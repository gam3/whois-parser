#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca2'


class Whois
  class Parsers

    # Parser for the whois1.nic.bi server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class Whois1NicBi < BaseCocca2
    end

  end
end
