package main

import (
	"fmt"
	"os"

	"acab.enterprises/dismantl/squeeler"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
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

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	log.Logger = log.With().Caller().Logger()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	fmt.Print(banner)

	sqlr, err := squeeler.NewSqlrFromCmdLine(os.Args, true)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}

	err = sqlr.Connect()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}

	switch sqlr.Cmd {
	case squeeler.SQLR_ENUM_LOCAL:
		sqlr.EnumLocal()
	case squeeler.SQLR_QUERY:
		if err = sqlr.Query(sqlr.QueryString, sqlr.QueryTimeout); err != nil {
			log.Fatal().Err(err).Msg("Failed to execute query")
		}
	case squeeler.SQLR_ENUM_LINK:
		sqlr.EnumLink(sqlr.EnumLinkChain)
	case squeeler.SQLR_ENABLE_RPC:
		if err = sqlr.EnableRpc(sqlr.RpcTarget); err != nil {
			log.Fatal().Err(err).Msg("Failed to enable RPC on target server")
		}
	case squeeler.SQLR_CAPTURE_HASH:
		if err = sqlr.CaptureHash(sqlr.SmbServer, sqlr.SmbShare); err != nil {
			log.Fatal().Err(err).Msg("Failed to capture hash")
		}
	case squeeler.SQLR_XP_CMDSHELL:
		results, err := sqlr.ExecXpCmdShell(sqlr.XpCommand, sqlr.XpTimeout)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to execute command via xp_cmdshell")
		}
		fmt.Println("Output from command:", results)
	case squeeler.SQLR_SP_OA:
		if err = sqlr.ExecSpOa(sqlr.SpOaCommand, sqlr.SpOaTimeout); err != nil {
			log.Fatal().Err(err).Msg("Failed to execute command via sp_OACreate")
		}
	case squeeler.SQLR_ASSEMBLY_EXEC:
		results, err := sqlr.ExecAssembly(sqlr.AssemblyCommand, sqlr.AssemblyTimeout)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to execute command via embedded assembly")
		}
		fmt.Println("Output from command:", results)
	case squeeler.SQLR_EXEC_LINK:
		results, err := sqlr.ExecLinkCommand(sqlr.ExecLinkCommandString, sqlr.ExecLinkTimeout, sqlr.ExecLinkChain)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to execute command on linked server via xp_cmdshell")
		}
		fmt.Println("Output from command:", results)
	case squeeler.SQLR_SHELL:
		sqlr.RunShell()
	default:
		log.Fatal().Msg("Must specify command")
	}
}
