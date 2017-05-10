#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'whois.centralnic.com.rb'


class Whois
  class Parsers

    # Parser for the whois.nic.pw server.
    #
    # It aliases the whois.centralnic.com parser because
    # the .PW TLD is powered by Centralnic.
    class WhoisNicPw < WhoisCentralnicCom
    end

  end
end
