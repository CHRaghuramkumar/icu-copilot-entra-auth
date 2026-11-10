import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Logger } from '@nestjs/common';
import type { EmrUser, EntraLink, UserDirectory } from './user-directory';

/**
 * Dev/demo directory backed by a JSON file. Links made at sign-in are kept in
 * memory only, so a restart forgets them (the production directory stores them
 * in the EMR, e.g. a `core.users.entra_oid` column).
 */
export class FileUserDirectory implements UserDirectory {
  private readonly logger = new Logger(FileUserDirectory.name);
  private readonly users: EmrUser[];

  constructor(users: EmrUser[]) {
    this.users = users.map((u) => ({ ...u, email: u.email.trim().toLowerCase() }));
  }

  static fromFile(path: string): FileUserDirectory {
    const absolute = resolve(path);
    const parsed: unknown = JSON.parse(readFileSync(absolute, 'utf8'));
    if (!Array.isArray(parsed)) throw new Error(`${absolute} must contain a JSON array of users.`);
    const directory = new FileUserDirectory(parsed as EmrUser[]);
    directory.logger.log(`Loaded ${parsed.length} users from ${absolute}`);
    return directory;
  }

  async findByEntraLink(link: EntraLink): Promise<EmrUser | null> {
    return this.users.find((u) => u.entra && sameLink(u.entra, link)) ?? null;
  }

  async findByEmail(email: string): Promise<EmrUser[]> {
    const wanted = email.trim().toLowerCase();
    return this.users.filter((u) => u.email === wanted);
  }

  async findById(userId: string): Promise<EmrUser | null> {
    return this.users.find((u) => u.userId === userId) ?? null;
  }

  async linkEntra(userId: string, link: EntraLink): Promise<void> {
    const user = this.users.find((u) => u.userId === userId);
    if (!user) throw new Error(`Unknown user ${userId}`);
    user.entra = { tenantId: link.tenantId.toLowerCase(), oid: link.oid.toLowerCase() };
  }
}

export function sameLink(a: EntraLink, b: EntraLink): boolean {
  return a.tenantId.toLowerCase() === b.tenantId.toLowerCase() && a.oid.toLowerCase() === b.oid.toLowerCase();
}
