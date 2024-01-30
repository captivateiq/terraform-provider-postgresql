---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "postgresql_default_privileges Resource - terraform-provider-postgresql"
subcategory: ""
description: |-
  
---

# postgresql_default_privileges (Resource)





<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `database` (String) The database to grant default privileges for this role
- `object_type` (String) The PostgreSQL object type to set the default privileges on (one of: table, sequence, function, type, schema)
- `owner` (String) Target role for which to alter default privileges.
- `privileges` (Set of String) The list of privileges to apply as default privileges
- `role` (String) The name of the role to which grant default privileges on

### Optional

- `schema` (String) The database schema to set default privileges for this role
- `with_grant_option` (Boolean) Permit the grant recipient to grant it to others

### Read-Only

- `id` (String) The ID of this resource.