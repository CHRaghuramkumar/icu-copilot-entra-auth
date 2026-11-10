/**
 * Where EMR users come from. The auth service never invents users: a person can
 * sign in only if the EMR already knows them.
 *
 * Today there is one implementation, {@link FileUserDirectory}, for local dev
 * and demos. The production implementation will call the EMR backend (contract
 * in docs/emr-backend-integration.md), which owns `core.users`.
 */
export const USER_DIRECTORY = Symbol('USER_DIRECTORY');

/** Mirrors the EMR `Role` enum (modern-emr-backend src/common/enums/role.enum.ts). */
export type EmrRole =
  | 'ADMIN'
  | 'CONSULTANT'
  | 'WARD_DOCTOR'
  | 'INTENSIVIST'
  | 'WARD_NURSE'
  | 'INCHARGE_NURSE'
  | 'NURSE_HOD'
  | 'DIETICIAN'
  | 'SYSTEM_ADMIN'
  | 'SYSTEM';

export interface EntraLink {
  tenantId: string;
  oid: string;
}

export interface EmrUser {
  /** `core.users.id` */
  userId: string;
  orgId: string;
  email: string;
  displayName: string;
  roles: EmrRole[];
  regionId?: string;
  locationId?: string;
  active: boolean;
  /** Set after the first successful Entra sign-in. */
  entra?: EntraLink;
}

export interface UserDirectory {
  findByEntraLink(link: EntraLink): Promise<EmrUser | null>;
  /** Email is unique per org in the EMR, not globally, so this can return several users. */
  findByEmail(email: string): Promise<EmrUser[]>;
  findById(userId: string): Promise<EmrUser | null>;
  /** Remember the Entra identity so later sign-ins match on `oid`, not email. */
  linkEntra(userId: string, link: EntraLink): Promise<void>;
}
