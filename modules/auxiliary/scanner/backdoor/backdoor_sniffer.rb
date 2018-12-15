##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'net/https'
require 'uri'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  ##
  # Initialize the module configurations
  ##
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Backdoor Sniffer',
      'Description' => %q{
        This module will attempt to sniff out well known backdoors hidden in popular directories and setup/backup files 
        that should not be public facing. The list of directories and page names are taken from various repositories of
        backdoors.
      },
      'Author' =>
        [
          'h4cklife',
        ],
      'License' => MSF_LICENSE
      )
    )

    deregister_options('RHOST', 'DigestAuthIIS', 'NTLM::SendLM',
      'NTLM::SendNTLM', 'VHOST', 'RPORT', 'NTLM::SendSPN', 'NTLM::UseLMKey',
      'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2')

    register_options(
      [
				OptString.new('DOMAIN', [true, 'Target domain']),
        OptString.new('OUTFILE', [false, 'A filename to store the results']),
				OptBool.new('DATABASE', [false, 'Add search results to thea loot database', false]),
				OptBool.new('SSL', [false, 'Use SSL', false]),
				OptBool.new('VERBOSE', [false, 'Verbose mode', false]),
      ], self.class)

  end

  ##
  # Request the page
  ##
  def bds_req(bdurl)
    uri = URI.parse(bdurl) 
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = datastore['SSL']
    request = Net::HTTP::Get.new(uri.request_uri)
    res = http.request(request)

    if res and res.body.nil? || res.body == ""
			return
    end

    if res
      results = res
      return results
    else
      return 'server_response_error'
    end
  end

  ##
  # Save the loot to a file
  ##
  def save_output(data)
    ::File.open(datastore['OUTFILE'], 'wb') do |f|
      f.write(data)
      print_status("Saved results in #{datastore['OUTFILE']}")
    end
  end

  ##
  # Verify the domain is resolvable
  ##
  def bds_resolvable?
    begin
      Rex::Socket.resolv_to_dotted(datastore['DOMAIN'])
    rescue RuntimeError, SocketError
      return false
    end

    true
  end

  ##
  # Run the module
  ##
  def run
    unless bds_resolvable?
      print_error("Unable to resolve target domain")
      return
    end

    print_status('Initializing scan, please wait...')

		directories = ['/', '/public/', '/cgi-bin/', '/sys/', '/root/', '/wp-content/uploads/', '/utilerias/',
    '/wp-content/themes/headway-166/library/resources/timthumb/', '/wp-content/themes/headway-2013/library/resources/timthumb/',
    '/PAGE_GRAPHICS/', '/images/', '/wp-content/themes/OptimizePress/', '/flowplayer/', '/wp-admin/',
    '/wp-content/plugins/', '/wp-content/themes/', '/wp-content/images/', '/includes/', '/wp-includes/', '/template/', '/templates/', '/themes/', '/skins/', '/tmpl/']

    pages = ['sistems.php', 'log.php', "3.php", "x.php", "X.php", "shell.php", "cookie.txt", "pass.txt", "timthumb.php", "timthumbs.php", "thumbnail.php", "shells.txt", "Commands.php",
    "uploader.php", "version.txt", "phpinfo.php", "test.php", "eval.php", "evil.php", "x2300.php", "casus15.php", "cgitelnet.php", "CmdAsp.asp",
    "dingen.php", "entrika.php", "529.php", "accept_language.php", "Ajax_PHP_Command_Shell.php", "AK-74.php", "AK-74.asp", "Antichat_Shell.php", "antichat.php",
    "aspydrv.php", "ayyildiz.php", "azrailphp.php", "b374k.php", "backupsql.php", "c0derz_shell.php", "c0derzshell.php", "c99", "locus7.php", "locus.php", "madnet.php",
    "madshell.php", "casus.php", "cmdasp.asp", "cpanel.php", "crystalshell.php", "cw.php", "cybershell.php", "dC3.php", "diveshell.php", "dive.php", "dtool.php", "erne.php",
    "fatal.php", "findsock.php", "ftpsearch.php", "g00nshell.php", "gamma.php", "gfs.php", "go-shell.php",
    "h4ntu.php", "ironshell.php", "kadot.php", "ka_ushell.php", "kral.php", "klasvayv.php",
    "lolipop.php", "Macker.php", "megabor.php", "matamu.php", "lostdc.php", "myshell.php", "mysql_tool.php", "mysql_web.php", "NCC-Shell.php", "nshell", "php-backdoor.php", "PHANTASMA.php",
    "predator.php", "pws.php", "qsd-php", "reader.asp", "ru24.php", "safe0ver.php","rootshell.php", "RemExp", "simattacker.php", "simshell.php", "simple-backdoor.php", "sosyete.asp",
    "small.php", "stres.php", "tryag.php", "toolaspshell.asp", "stnc.asp", "sincap.asp", "winx.asp", "Upload.php", "zaco.asp", "zehir.asp", "zyklon.asp",
    "a.php", "bd.php", "thumbnail.php", "timthumb.php", "timthumbs.php", "config.php", "router.php", "admin.php",
    "config.php", "controller.php", "cnc.php", "upload.php", "setup.php", "mysql.php", "phpinfo.php", "database.php", "config.inc.php",
    "connector.php", "example.php", "sql.php", "auth.php", "backup.php", "mysqli.php", "php.php", "json.php",
    "file_manager.php", "sendmail.php", "cron.php", "password.php", "setting.ini.php", "server.php", "database.mysqli.php", "edituser.php", "admin_header.php",
    'Server.php', 'xmlrpcs.php', 'uploadfile.php', 'functions.inc.php']


		verbose = datastore['VERBOSE']

    ssl = datastore['SSL']

    if ssl
      base = 'https://' + datastore['DOMAIN']
    else 
      base = 'http://' + datastore['DOMAIN']
    end

		found = 0
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'Backdoor Sniffer Results',
      'Indent'  => 1,
      'Columns' => ['Domain', 'Path', 'Page']
    )
		directories.each do |dir|
			pages.each do |page|
				bdurl = base+dir+page
				if verbose 
					print_status("Checking " + bdurl)
				end
				results = bds_req(bdurl)

    		if results.code == '404'
					if verbose
      			print_error('Returned 404 for ' + bdurl)
					end
				else
					report_loot(:host => '127.0.0.1',
    				:service => '',
    			  :content => '',
    			  :type => 'Backdoor',
    			  :name => page,
    			  :info => base,
    			  :path => dir
    			) if datastore['DATABASE']

    			tbl << [base, dir, page]

					if verbose
 	     			print_good("Returned " + results.code + " for " + bdurl)
					end

					found = found + 1
    		end
			end

		end

   	print_line
   	print_line("#{tbl}")
    
    save_output(tbl) if datastore['OUTFILE']
		print_status("Total: #{found} results found")
  end
end
