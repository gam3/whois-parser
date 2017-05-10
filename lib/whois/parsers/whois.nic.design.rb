#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'whois.centralnic.com'


class Whois
  class Parsers

    # Parser for the whois.nic.design server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicDesign < WhoisCentralnicCom
    end

  end
end
