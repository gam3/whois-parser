#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias'


class Whois
  class Parsers

    # Parser for the whois.dotmobiregistry.net server.
    class WhoisDotmobiregistryNet < BaseAfilias
    end

  end
end
