import json
import sys
import os
from haralyzer import HarParser, HarPage
from geoip import geolite2
from dns import resolver
import pycountry

DIR = "../ALL_HARs"
TXT_DESTINATION = "../TXTs/"

def countryCodeToName(code):
    return pycountry.countries.get(alpha_2=code).name

def containsForeignIP(ip_list):
    for ip in ip_list:
        geoip_res = geolite2.lookup(ip.address)
        if geoip_res != None and geoip_res.country != "US":
            return geoip_res
    return geoip_res

def analyzeAll():
    num_entries = 0
    no_dns = 0
    no_resolve = 0
    foreign_outbound = 0
    domestic_outbound = 0
    no_country = 0
    no_dns = 0
    countries = dict()
    continents = dict()
    for f in os.scandir(DIR):
        print("Now analyzing {}:".format(f.name))
        har_parser = HarParser.from_file(f)
        countries_per_app = dict()
        continents_per_app = dict()
        entries_per_app = 0
        txt_name = f.name.split('.')[0] + ".txt"
        new_txt = open(TXT_DESTINATION + txt_name, 'w')
        hasText = False
        #print("GOING TO LOOK AT PAGES: " + str(len(har_parser.pages)))
        for page in har_parser.pages:
            #print("GOING TO LOOK AT ENTRIES: " + str(len(page.entries)))
            for entry in page.entries:
                entries_per_app +=1
                num_entries += 1
                #print (entry.request.url)
                try:
                    domain = entry.request.host
                    if domain == None:
                        domain = entry.request.url.split("/")[2]
                    res = resolver.resolve(domain, 'A')
                except:
                    toWrite = "DNS Query does not exist with url: " + entry.request.url + "\n"
                    no_dns += 1
                    #print(toWrite)
                    new_txt.write(toWrite)
                else:
                    # # need to check if ip address is outside of us
                    geoip_res = containsForeignIP(res)
                    toWrite = ""
                    if geoip_res == None:
                        toWrite = "Could not resolve: " + domain + "\n"
                        no_resolve += 1
                    elif geoip_res.country == None:
                        no_country += 1
                        toWrite = "No country, request sent to foreign continent " + geoip_res.continent + " with ip " + geoip_res.ip + "\n"
                    # output body of request/response if content is in readable encoding
                    elif geoip_res.country != 'US':
                        foreign_outbound += 1
                        country_name = countryCodeToName(geoip_res.country)
                        toWrite = "Foreign IP: " + geoip_res.ip + " Foreign Country: " + country_name + " URL: " + entry.request.url + "\n"
                        print("Foreign domain: " + domain + "routing to " + country_name)
                        # add conutry name to dictionary and increment count
                        countries[country_name] = countries.get(country_name, 0) + 1
                        countries_per_app[country_name] = countries_per_app.get(country_name, 0) + 1
                        # continent data to dictionary
                        continents[geoip_res.continent] = continents.get(geoip_res.continent, 0) + 1
                        continents_per_app[geoip_res.continent] = continents_per_app.get(geoip_res.continent, 0) + 1
                    else:
                        domestic_outbound += 1
                        continue
                    #print(toWrite)
                    new_txt.write(toWrite)

                    hasText = True

        # adds summary about the country data for each txt file
        print("NUMBER OF ENTRIES RUNNING TOTAL:" + str(num_entries))
        print("NUMBER OF ENTRIES THIS APP: " + str (entries_per_app))
        print()
        print("--------------------------------------------------------------------------------")
        new_txt.write("--------------------------------------------------------------------------------\n")
        new_txt.write("NUMBER OF ENTRIES IN  : " + str(entries_per_app))
        new_txt.write(str(continents_per_app) + "\n" + str(countries_per_app))
        new_txt.close()
        if not hasText:
            os.remove(TXT_DESTINATION + txt_name)
    print("Analyzed {} requests/responses.".format(num_entries))
    print("{} requests sent to a foreign IP.".format(foreign_outbound))
    print("{} requests sent to an American IP.".format(domestic_outbound))
    print("Could not resolve the DNS record of {} requests/responses.".format(no_resolve))
    print("{} requests/responses did not have a country code in their DNS record.".format(no_country))
    print("Could not find the DNS record for {} requests/responses.".format(no_dns))
    print("Now printing all countries and their count:\n " + str(countries))

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "-r":
        print("Now deleting TXTs folder.")
        for f in os.listdir(TXT_DESTINATION):
            os.remove(TXT_DESTINATION + f)

    analyzeAll()
