package postgresql

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/lib/pq"
)

const (
	dbAllowConnsAttr = "allow_connections"
	dbCTypeAttr      = "lc_ctype"
	dbCollationAttr  = "lc_collate"
	dbConnLimitAttr  = "connection_limit"
	dbEncodingAttr   = "encoding"
	dbIsTemplateAttr = "is_template"
	dbNameAttr       = "name"
	dbOwnerAttr      = "owner"
	dbTablespaceAttr = "tablespace_name"
	dbTemplateAttr   = "template"
)

func resourcePostgreSQLDatabase() *schema.Resource {
	return &schema.Resource{
		Create: resourcePostgreSQLDatabaseCreate,
		Read:   resourcePostgreSQLDatabaseRead,
		Update: resourcePostgreSQLDatabaseUpdate,
		Delete: resourcePostgreSQLDatabaseDelete,
		Exists: resourcePostgreSQLDatabaseExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			dbNameAttr: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The PostgreSQL database name to connect to",
			},
			dbOwnerAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The ROLE which owns the database",
			},
			dbTemplateAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "The name of the template from which to create the new database",
			},
			dbEncodingAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "Character set encoding to use in the new database",
			},
			dbCollationAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "Collation order (LC_COLLATE) to use in the new database",
			},
			dbCTypeAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "Character classification (LC_CTYPE) to use in the new database",
			},
			dbTablespaceAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of the tablespace that will be associated with the new database",
			},
			dbConnLimitAttr: {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      -1,
				Description:  "How many concurrent connections can be made to this database",
				ValidateFunc: validateConnLimit,
			},
			dbAllowConnsAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "If false then no one can connect to this database",
			},
			dbIsTemplateAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "If true, then this database can be cloned by any user with CREATEDB privileges",
			},
		},
	}
}

func resourcePostgreSQLDatabaseCreate(d *schema.ResourceData, meta interface{}) error {
	c := meta.(*Client)

	c.catalogLock.Lock()
	defer c.catalogLock.Unlock()

	dbName := d.Get(dbNameAttr).(string)
	b := bytes.NewBufferString("CREATE DATABASE ")
	fmt.Fprint(b, pq.QuoteIdentifier(dbName))

	// Needed in order to set the owner of the db if the connection user is not a
	// superuser
	err := grantRoleMembership(c.DB(), d.Get(dbOwnerAttr).(string), c.config.Username)
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("Error adding connection user (%q) to ROLE %q: {{err}}", c.config.Username, d.Get(dbOwnerAttr).(string)), err)
	}
	defer func() {
		//undo the grant if the connection user is not a superuser
		err = revokeRoleMembership(c.DB(), d.Get(dbOwnerAttr).(string), c.config.Username)
		if err != nil {
			err = errwrap.Wrapf(fmt.Sprintf("Error removing connection user (%q) from ROLE %q: {{err}}", c.config.Username, d.Get(dbOwnerAttr).(string)), err)
		}
	}()

	// Handle each option individually and stream results into the query
	// buffer.

	switch v, ok := d.GetOk(dbOwnerAttr); {
	case ok:
		fmt.Fprint(b, " OWNER ", pq.QuoteIdentifier(v.(string)))
	default:
		// No owner specified in the config, default to using
		// the connecting username.
		fmt.Fprint(b, " OWNER ", pq.QuoteIdentifier(c.config.Username))
	}

	switch v, ok := d.GetOk(dbTemplateAttr); {
	case ok && strings.ToUpper(v.(string)) == "DEFAULT":
		fmt.Fprint(b, " TEMPLATE DEFAULT")
	case ok:
		fmt.Fprint(b, " TEMPLATE ", pq.QuoteIdentifier(v.(string)))
	case v.(string) == "":
		fmt.Fprint(b, " TEMPLATE template0")
	}

	switch v, ok := d.GetOk(dbEncodingAttr); {
	case ok && strings.ToUpper(v.(string)) == "DEFAULT":
		fmt.Fprintf(b, " ENCODING DEFAULT")
	case ok:
		fmt.Fprintf(b, " ENCODING '%s' ", pqQuoteLiteral(v.(string)))
	case v.(string) == "":
		fmt.Fprint(b, ` ENCODING 'UTF8'`)
	}

	switch v, ok := d.GetOk(dbCollationAttr); {
	case ok && strings.ToUpper(v.(string)) == "DEFAULT":
		fmt.Fprintf(b, " LC_COLLATE DEFAULT")
	case ok:
		fmt.Fprintf(b, " LC_COLLATE '%s' ", pqQuoteLiteral(v.(string)))
	case v.(string) == "":
		fmt.Fprint(b, ` LC_COLLATE 'C'`)
	}

	switch v, ok := d.GetOk(dbCTypeAttr); {
	case ok && strings.ToUpper(v.(string)) == "DEFAULT":
		fmt.Fprintf(b, " LC_CTYPE DEFAULT")
	case ok:
		fmt.Fprintf(b, " LC_CTYPE '%s' ", pqQuoteLiteral(v.(string)))
	case v.(string) == "":
		fmt.Fprint(b, ` LC_CTYPE 'C'`)
	}

	switch v, ok := d.GetOk(dbTablespaceAttr); {
	case ok && strings.ToUpper(v.(string)) == "DEFAULT":
		fmt.Fprint(b, " TABLESPACE DEFAULT")
	case ok:
		fmt.Fprint(b, " TABLESPACE ", pq.QuoteIdentifier(v.(string)))
	}

	if c.featureSupported(featureDBAllowConnections) {
		val := d.Get(dbAllowConnsAttr).(bool)
		fmt.Fprint(b, " ALLOW_CONNECTIONS ", val)
	}

	{
		val := d.Get(dbConnLimitAttr).(int)
		fmt.Fprint(b, " CONNECTION LIMIT ", val)
	}

	if c.featureSupported(featureDBIsTemplate) {
		val := d.Get(dbIsTemplateAttr).(bool)
		fmt.Fprint(b, " IS_TEMPLATE ", val)
	}

	sql := b.String()
	if _, err := c.DB().Exec(sql); err != nil {
		return errwrap.Wrapf(fmt.Sprintf("Error creating database %q: {{err}}", dbName), err)
	}

	d.SetId(dbName)

	// Set err outside of the return so that the deferred revoke can override err
	// if necessary.
	err = resourcePostgreSQLDatabaseReadImpl(d, meta)
	return err
}

func resourcePostgreSQLDatabaseDelete(d *schema.ResourceData, meta interface{}) error {
	c := meta.(*Client)
	c.catalogLock.Lock()
	defer c.catalogLock.Unlock()

	dbName := d.Get(dbNameAttr).(string)

	if c.featureSupported(featureDBIsTemplate) {
		if isTemplate := d.Get(dbIsTemplateAttr).(bool); isTemplate {
			// Template databases must have this attribute cleared before
			// they can be dropped.
			if err := doSetDBIsTemplate(c, dbName, false); err != nil {
				return errwrap.Wrapf("Error updating database IS_TEMPLATE during DROP DATABASE: {{err}}", err)
			}
		}
	}

	if err := setDBIsTemplate(c, d); err != nil {
		return err
	}

	sql := fmt.Sprintf("DROP DATABASE %s", pq.QuoteIdentifier(dbName))
	if _, err := c.DB().Exec(sql); err != nil {
		return errwrap.Wrapf("Error dropping database: {{err}}", err)
	}

	d.SetId("")

	return nil
}

func resourcePostgreSQLDatabaseExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	c := meta.(*Client)
	c.catalogLock.RLock()
	defer c.catalogLock.RUnlock()

	var dbName string
	err := c.DB().QueryRow("SELECT d.datname from pg_database d WHERE datname=$1", d.Id()).Scan(&dbName)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

func resourcePostgreSQLDatabaseRead(d *schema.ResourceData, meta interface{}) error {
	c := meta.(*Client)
	c.catalogLock.RLock()
	defer c.catalogLock.RUnlock()

	return resourcePostgreSQLDatabaseReadImpl(d, meta)
}

func resourcePostgreSQLDatabaseReadImpl(d *schema.ResourceData, meta interface{}) error {
	c := meta.(*Client)

	dbId := d.Id()
	var dbName, ownerName string
	err := c.DB().QueryRow("SELECT d.datname, pg_catalog.pg_get_userbyid(d.datdba) from pg_database d WHERE datname=$1", dbId).Scan(&dbName, &ownerName)
	switch {
	case err == sql.ErrNoRows:
		log.Printf("[WARN] PostgreSQL database (%q) not found", dbId)
		d.SetId("")
		return nil
	case err != nil:
		return errwrap.Wrapf("Error reading database: {{err}}", err)
	}

	var dbEncoding, dbCollation, dbCType, dbTablespaceName string
	var dbConnLimit int

	columns := []string{
		"pg_catalog.pg_encoding_to_char(d.encoding)",
		"d.datcollate",
		"d.datctype",
		"ts.spcname",
		"d.datconnlimit",
	}

	dbSQLFmt := `SELECT %s ` +
		`FROM pg_catalog.pg_database AS d, pg_catalog.pg_tablespace AS ts ` +
		`WHERE d.datname = $1 AND d.dattablespace = ts.oid`
	dbSQL := fmt.Sprintf(dbSQLFmt, strings.Join(columns, ", "))
	err = c.DB().QueryRow(dbSQL, dbId).
		Scan(
			&dbEncoding,
			&dbCollation,
			&dbCType,
			&dbTablespaceName,
			&dbConnLimit,
		)
	switch {
	case err == sql.ErrNoRows:
		log.Printf("[WARN] PostgreSQL database (%q) not found", dbId)
		d.SetId("")
		return nil
	case err != nil:
		return errwrap.Wrapf("Error reading database: {{err}}", err)
	}

	d.Set(dbNameAttr, dbName)
	d.Set(dbOwnerAttr, ownerName)
	d.Set(dbEncodingAttr, dbEncoding)
	d.Set(dbCollationAttr, dbCollation)
	d.Set(dbCTypeAttr, dbCType)
	d.Set(dbTablespaceAttr, dbTablespaceName)
	d.Set(dbConnLimitAttr, dbConnLimit)
	dbTemplate := d.Get(dbTemplateAttr).(string)
	if dbTemplate == "" {
		dbTemplate = "template0"
	}
	d.Set(dbTemplateAttr, dbTemplate)

	if c.featureSupported(featureDBAllowConnections) {
		var dbAllowConns bool
		dbSQL := fmt.Sprintf(dbSQLFmt, "d.datallowconn")
		err = c.DB().QueryRow(dbSQL, dbId).Scan(&dbAllowConns)
		if err != nil {
			return errwrap.Wrapf("Error reading ALLOW_CONNECTIONS property for DATABASE: {{err}}", err)
		}

		d.Set(dbAllowConnsAttr, dbAllowConns)
	}

	if c.featureSupported(featureDBIsTemplate) {
		var dbIsTemplate bool
		dbSQL := fmt.Sprintf(dbSQLFmt, "d.datistemplate")
		err = c.DB().QueryRow(dbSQL, dbId).Scan(&dbIsTemplate)
		if err != nil {
			return errwrap.Wrapf("Error reading IS_TEMPLATE property for DATABASE: {{err}}", err)
		}

		d.Set(dbIsTemplateAttr, dbIsTemplate)
	}

	return nil
}

func resourcePostgreSQLDatabaseUpdate(d *schema.ResourceData, meta interface{}) error {
	c := meta.(*Client)
	c.catalogLock.Lock()
	defer c.catalogLock.Unlock()

	if err := setDBName(c.DB(), d); err != nil {
		return err
	}

	if err := setDBOwner(c, d); err != nil {
		return err
	}

	if err := setDBTablespace(c.DB(), d); err != nil {
		return err
	}

	if err := setDBConnLimit(c.DB(), d); err != nil {
		return err
	}

	if err := setDBAllowConns(c, d); err != nil {
		return err
	}

	if err := setDBIsTemplate(c, d); err != nil {
		return err
	}

	// Empty values: ALTER DATABASE name RESET configuration_parameter;

	return resourcePostgreSQLDatabaseReadImpl(d, meta)
}

func setDBName(db *sql.DB, d *schema.ResourceData) error {
	if !d.HasChange(dbNameAttr) {
		return nil
	}

	oraw, nraw := d.GetChange(dbNameAttr)
	o := oraw.(string)
	n := nraw.(string)
	if n == "" {
		return errors.New("Error setting database name to an empty string")
	}

	sql := fmt.Sprintf("ALTER DATABASE %s RENAME TO %s", pq.QuoteIdentifier(o), pq.QuoteIdentifier(n))
	if _, err := db.Exec(sql); err != nil {
		return errwrap.Wrapf("Error updating database name: {{err}}", err)
	}
	d.SetId(n)

	return nil
}

func setDBOwner(c *Client, d *schema.ResourceData) error {
	if !d.HasChange(dbOwnerAttr) {
		return nil
	}

	owner := d.Get(dbOwnerAttr).(string)
	if owner == "" {
		return nil
	}

	//needed in order to set the owner of the db if the connection user is not a superuser
	err := grantRoleMembership(c.DB(), d.Get(dbOwnerAttr).(string), c.config.Username)
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("Error adding connection user (%q) to ROLE %q: {{err}}", c.config.Username, d.Get(dbOwnerAttr).(string)), err)
	}
	defer func() {
		// undo the grant if the connection user is not a superuser
		err = revokeRoleMembership(c.DB(), d.Get(dbOwnerAttr).(string), c.config.Username)
		if err != nil {
			err = errwrap.Wrapf(fmt.Sprintf("Error removing connection user (%q) from ROLE %q: {{err}}", c.config.Username, d.Get(dbOwnerAttr).(string)), err)
		}
	}()

	dbName := d.Get(dbNameAttr).(string)
	sql := fmt.Sprintf("ALTER DATABASE %s OWNER TO %s", pq.QuoteIdentifier(dbName), pq.QuoteIdentifier(owner))
	if _, err := c.DB().Exec(sql); err != nil {
		return errwrap.Wrapf("Error updating database OWNER: {{err}}", err)
	}

	return err
}

func setDBTablespace(db *sql.DB, d *schema.ResourceData) error {
	if !d.HasChange(dbTablespaceAttr) {
		return nil
	}

	tbspName := d.Get(dbTablespaceAttr).(string)
	dbName := d.Get(dbNameAttr).(string)
	var sql string
	if tbspName == "" || strings.ToUpper(tbspName) == "DEFAULT" {
		sql = fmt.Sprintf("ALTER DATABASE %s RESET TABLESPACE", pq.QuoteIdentifier(dbName))
	} else {
		sql = fmt.Sprintf("ALTER DATABASE %s SET TABLESPACE %s", pq.QuoteIdentifier(dbName), pq.QuoteIdentifier(tbspName))
	}

	if _, err := db.Exec(sql); err != nil {
		return errwrap.Wrapf("Error updating database TABLESPACE: {{err}}", err)
	}

	return nil
}

func setDBConnLimit(db *sql.DB, d *schema.ResourceData) error {
	if !d.HasChange(dbConnLimitAttr) {
		return nil
	}

	connLimit := d.Get(dbConnLimitAttr).(int)
	dbName := d.Get(dbNameAttr).(string)
	sql := fmt.Sprintf("ALTER DATABASE %s CONNECTION LIMIT = $1", pq.QuoteIdentifier(dbName))
	if _, err := db.Exec(sql, connLimit); err != nil {
		return errwrap.Wrapf("Error updating database CONNECTION LIMIT: {{err}}", err)
	}

	return nil
}

func setDBAllowConns(c *Client, d *schema.ResourceData) error {
	if !d.HasChange(dbAllowConnsAttr) {
		return nil
	}

	if !c.featureSupported(featureDBAllowConnections) {
		return fmt.Errorf("PostgreSQL client is talking with a server (%q) that does not support database ALLOW_CONNECTIONS", c.version.String())
	}

	allowConns := d.Get(dbAllowConnsAttr).(bool)
	dbName := d.Get(dbNameAttr).(string)
	sql := fmt.Sprintf("ALTER DATABASE %s ALLOW_CONNECTIONS $1", pq.QuoteIdentifier(dbName))
	if _, err := c.DB().Exec(sql, allowConns); err != nil {
		return errwrap.Wrapf("Error updating database ALLOW_CONNECTIONS: {{err}}", err)
	}

	return nil
}

func setDBIsTemplate(c *Client, d *schema.ResourceData) error {
	if !d.HasChange(dbIsTemplateAttr) {
		return nil
	}

	if err := doSetDBIsTemplate(c, d.Get(dbNameAttr).(string), d.Get(dbIsTemplateAttr).(bool)); err != nil {
		return errwrap.Wrapf("Error updating database IS_TEMPLATE: {{err}}", err)
	}

	return nil
}

func doSetDBIsTemplate(c *Client, dbName string, isTemplate bool) error {
	if !c.featureSupported(featureDBIsTemplate) {
		return fmt.Errorf("PostgreSQL client is talking with a server (%q) that does not support database IS_TEMPLATE", c.version.String())
	}

	sql := fmt.Sprintf("ALTER DATABASE %s IS_TEMPLATE $1", pq.QuoteIdentifier(dbName))
	if _, err := c.DB().Exec(sql, isTemplate); err != nil {
		return errwrap.Wrapf("Error updating database IS_TEMPLATE: {{err}}", err)
	}

	return nil
}

func grantRoleMembership(db *sql.DB, dbOwner string, connUsername string) error {
	if dbOwner != "" && dbOwner != connUsername {
		sql := fmt.Sprintf("GRANT %s TO %s", pq.QuoteIdentifier(dbOwner), pq.QuoteIdentifier(connUsername))
		if _, err := db.Exec(sql); err != nil {
			// is already member or role
			if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
				return nil
			}
			return errwrap.Wrapf("Error granting membership: {{err}}", err)
		}
	}
	return nil
}

func revokeRoleMembership(db *sql.DB, dbOwner string, connUsername string) error {
	if dbOwner != "" && dbOwner != connUsername {
		sql := fmt.Sprintf("REVOKE %s FROM %s", pq.QuoteIdentifier(dbOwner), pq.QuoteIdentifier(connUsername))
		if _, err := db.Exec(sql); err != nil {
			return errwrap.Wrapf("Error revoking membership: {{err}}", err)
		}
	}
	return nil
}