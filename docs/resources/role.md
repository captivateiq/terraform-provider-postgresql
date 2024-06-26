---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "postgresql_role Resource - terraform-provider-postgresql"
subcategory: ""
description: |-
  
---

# postgresql_role (Resource)





<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) The name of the role

### Optional

- `assume_role` (String) Role to switch to at login
- `bypass_row_level_security` (Boolean) Determine whether a role bypasses every row-level security (RLS) policy
- `connection_limit` (Number) How many concurrent connections can be made with this role
- `create_database` (Boolean) Define a role's ability to create databases
- `create_role` (Boolean) Determine whether this role will be permitted to create new roles
- `encrypted` (String, Deprecated)
- `encrypted_password` (Boolean) Control whether the password is stored encrypted in the system catalogs
- `idle_in_transaction_session_timeout` (Number) Terminate any session with an open transaction that has been idle for longer than the specified duration in milliseconds
- `inherit` (Boolean) Determine whether a role "inherits" the privileges of roles it is a member of
- `lock_timeout` (Number) Abort any statement that waits longer than the specified amount of time while attempting to acquire a lock on a table, index, row, or other database object
- `login` (Boolean) Determine whether a role is allowed to log in
- `password` (String, Sensitive) Sets the role's password
- `replication` (Boolean) Determine whether a role is allowed to initiate streaming replication or put the system in and out of backup mode
- `roles` (Set of String) Role(s) to grant to this new role
- `search_path` (List of String) Sets the role's search path
- `skip_drop_role` (Boolean) Skip actually running the DROP ROLE command when removing a ROLE from PostgreSQL
- `skip_reassign_owned` (Boolean) Skip actually running the REASSIGN OWNED command when removing a role from PostgreSQL
- `statement_timeout` (Number) Abort any statement that takes more than the specified number of milliseconds
- `superuser` (Boolean) Determine whether the new role is a "superuser"
- `valid_until` (String) Sets a date and time after which the role's password is no longer valid

### Read-Only

- `id` (String) The ID of this resource.
