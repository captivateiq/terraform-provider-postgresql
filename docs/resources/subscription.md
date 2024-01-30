---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "postgresql_subscription Resource - terraform-provider-postgresql"
subcategory: ""
description: |-
  
---

# postgresql_subscription (Resource)





<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `conninfo` (String, Sensitive) The connection string to the publisher. It should follow the keyword/value format (https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING)
- `name` (String) The name of the subscription
- `publications` (Set of String) Names of the publications on the publisher to subscribe to

### Optional

- `create_slot` (Boolean) Specifies whether the command should create the replication slot on the publisher
- `database` (String) Sets the database to add the subscription for
- `slot_name` (String) Name of the replication slot to use. The default behavior is to use the name of the subscription for the slot name

### Read-Only

- `id` (String) The ID of this resource.