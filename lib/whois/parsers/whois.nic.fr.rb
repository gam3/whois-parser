#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_nic_fr'


class Whois
  class Parsers

    # Parser for the whois.nic.fr server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicFr < BaseNicFr
    end

  end
end
