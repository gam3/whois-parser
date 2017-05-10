#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/iana'


class Whois
  class Parsers

    # Parser for the whois.iana.org server.
    class WhoisGodaddyCom < Base
      include Scanners::Scannable

      self.scanner = Scanners::Iana


      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /This query returned 0 objects|organisation: Not assigned/)
      end

      property_supported :registered? do
        !available?
      end

      property_supported :registrar do
	name = nil
	id = nil
        if (match = content_for_scanner.match(/Registrar: (.+?)\n/))
          name = match.to_a[1]
        end
        if (match = content_for_scanner.match(/Registrar IANA ID: (.+?)\n/))
          id = match.to_a[1]
        end
	Parser::Registrar.new(name: name.strip, id: id.strip)
      end

      property_supported :registrant_contacts do
        build_contact("organisation", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("administrative", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("technical", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :created_on do
        node("dates") { |raw| parse_time(raw["created"]) }
      end

      property_supported :updated_on do
        node("dates") { |raw| parse_time(raw["changed"]) }
      end

      property_not_supported :expires_on

      # Nameservers are listed in the following formats:
      #
      #   Name Server: dns2.gencat.cat 83.247.132.4
      #   Name Server: dns.gencat.net
      #
      property_supported :nameservers do
        content_for_scanner.scan(/Name Server:\s+(.+)\n/).flatten.map do |line|
          name, ipv4 = line.split(/\s+/)
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end


      private

      def build_contact(element, type)
        node(element) do |raw|
          if raw["organisation"] != "Not assigned"
            address = (raw["address"] || "").split("\n")
            Parser::Contact.new(
              :type         => type,
              :name         => raw["name"],
              :organization => raw["organisation"],
              :address      => address[0],
              :city         => address[1],
              :zip          => address[2],
              :country      => address[3],
              :phone        => raw["phone"],
              :fax          => raw["fax-no"],
              :email        => raw["e-mail"]
            )
          end
        end
      end

    end

  end
end
