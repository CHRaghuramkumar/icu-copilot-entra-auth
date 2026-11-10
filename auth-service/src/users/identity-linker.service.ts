import { Inject, Injectable, Logger } from '@nestjs/common';
import { AuthError } from '../common/auth-error';
import type { EntraIdentity } from '../entra/entra-token.verifier';
import { sameLink } from './file-user-directory';
import { USER_DIRECTORY, type EmrUser, type UserDirectory } from './user-directory';

/**
 * Finds the EMR user for a verified Entra identity.
 *
 * 1. Already linked? Match on Entra `oid` (stable even if the email changes).
 * 2. First sign-in: match on email, refuse if there is no match or more than one,
 *    then remember the `oid` so step 1 is used from now on.
 *
 * Never creates users: someone the EMR does not know cannot get in just by
 * having a hospital Microsoft account.
 */
@Injectable()
export class IdentityLinkerService {
  private readonly logger = new Logger(IdentityLinkerService.name);

  constructor(@Inject(USER_DIRECTORY) private readonly directory: UserDirectory) {}

  async resolve(identity: EntraIdentity): Promise<EmrUser> {
    const link = { tenantId: identity.tenantId, oid: identity.oid };

    const linked = await this.directory.findByEntraLink(link);
    if (linked) return assertActive(linked);

    const matches = await this.directory.findByEmail(identity.email);
    if (matches.length === 0) {
      this.logger.warn({ msg: 'Entra sign-in with no matching EMR user', oid: identity.oid });
      throw new AuthError(
        'USER_NOT_PROVISIONED',
        'You are signed in to Microsoft, but you are not set up in the EMR yet. Ask your EMR administrator.',
      );
    }
    if (matches.length > 1) {
      this.logger.warn({ msg: 'Entra email matches several EMR users', oid: identity.oid, count: matches.length });
      throw new AuthError(
        'USER_EMAIL_AMBIGUOUS',
        'Your email is used by more than one EMR account. Ask your EMR administrator to fix it.',
      );
    }

    const user = matches[0];
    // The EMR user is already tied to a different Microsoft account. Linking again
    // would let whoever now holds this email take over the account.
    if (user.entra && !sameLink(user.entra, link)) {
      this.logger.warn({ msg: 'EMR user already linked to another Entra identity', userId: user.userId });
      throw new AuthError(
        'USER_LINK_CONFLICT',
        'This EMR account is already linked to a different Microsoft account. Ask your EMR administrator.',
      );
    }

    assertActive(user);
    await this.directory.linkEntra(user.userId, link);
    this.logger.log({ msg: 'Linked Entra identity to EMR user', userId: user.userId, orgId: user.orgId });
    return { ...user, entra: link };
  }
}

function assertActive(user: EmrUser): EmrUser {
  if (!user.active) {
    throw new AuthError('USER_INACTIVE', 'Your EMR account is inactive. Ask your EMR administrator.');
  }
  return user;
}
