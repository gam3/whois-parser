#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'base_cocca'


class Whois
  class Parsers

    # Parser for the whois.nic.ec server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicEc < BaseCocca
      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          super()
        else
          registrar ? :registered : :available
          # Whois.bug!(ParserError, "Unable to parse status.")
        end
      end
    end

  end
end
