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
  # Initialize the moudle configurations
  ##
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Have I Been Pwned',
      'Description' => %q{
        Use the Have I Been Pwned API to locate data dumps that are related to a specific email account.
        Website: https://haveibeenpwned.com 
        API: https://haveibeenpwned.com/API/v2
      },
      'Author' =>
        [
          'h4cklife',
        ],
      'License' => MSF_LICENSE
      )
    )

    deregister_options('RHOST', 'DOMAIN', 'DigestAuthIIS', 'NTLM::SendLM',
      'NTLM::SendNTLM', 'VHOST', 'RPORT', 'NTLM::SendSPN', 'NTLM::UseLMKey',
      'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2')

    register_options(
      [
        OptString.new('QUERY', [true, 'Accounts you want to search for', 'null@null.com']),
        OptString.new('OUTFILE', [false, 'A filename to store the results']),
				OptBool.new('DATABASE', [false, 'Add search results to the database', false]),
				OptBool.new('SSL', [true, 'Use SSL', true]),
      ], self.class)
  end

  ##
  # Run the module
  ##
  def run
    unless hibp_resolvable?
      print_error("Unable to resolve haveibeenpwned.com")
      return
    end

    query = datastore['QUERY']

    print_status('Performing the request, please wait...')
    results = hibp_query(query)

    if results.nil?
      msg = "No results."
      print_error(msg)
      return
    end

    print_good("Target data dumps located...")

    print_status('If you set the outfile option your data will be saved. please wait...')

    tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'HIBP Results',
      'Indent'  => 1,
      'Columns' => ['Source', 'Id', 'Title', 'Date', 'EmailCount']
    )

    results.each do |res|
      source= res['Source'] ||= 'None'
      id = res['Id'] ||= 'None'
      title = res['Title'] ||= 'None'
      date = res['Date']  ||= 'None'
      emailcount  = res['EmailCount'] ||= 'None'

      report_loot(:host => '127.0.0.1',
        :service => '',
        :content => '',
        :type => 'DataDump',
        :name => title+":"+emailcount.to_s+"emails",
        :info => source,
        :path => id.to_s
      ) if datastore['DATABASE']


      tbl << [source, id, title, date, emailcount]
    end

    print_line
    print_line("#{tbl}")
    save_output(tbl) if datastore['OUTFILE']
    print_status("Total: #{results.length} results found")
  end

  ##
  # HIBP API Query
  ##
  def hibp_query(query)
    uri = URI.parse('https://haveibeenpwned.com/api/v2/pasteaccount/' +
      Rex::Text.uri_encode(query) )
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    request = Net::HTTP::Get.new(uri.request_uri)
    res = http.request(request)

    if res and res.body.nil? || res.body == ""
			return
    end

		if res and res.body =~ /<title>Have I been pwned? Page not found<\/title>/
      fail_with(Failure::BadConfig, 'Have I been pwned? Page not found')
    end

    if res
      results = ActiveSupport::JSON.decode(res.body)
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
  # Verify the host is resolvable
  ##
  def hibp_resolvable?
    begin
      Rex::Socket.resolv_to_dotted("haveibeenpwned.com")
    rescue RuntimeError, SocketError
      return false
    end

    true
  end

end
