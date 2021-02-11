# Trivyal Pursuit
# Crawls a k8s cluster for vulnerabilities
# Recommended: ruby trivyal_pursuit.rb -s HIGH,CRITICAL -p
require 'optparse'
require 'ostruct'
require 'json'
require 'byebug'

options = OpenStruct.new
options.severity = 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL'
OptionParser.new do |opt|
  opt.on('-s', '--severity HIGH,CRITICAL', 'vulnerability severity ratings to include') { |o| options.severity = o }
  opt.on('-p', '--patch-available', 'only include vulnerabilities with a patch available') { |o| options.patch_available = o }
  opt.on('-n', '--network-exploitable', 'only include network-exploitable vulnerabilities') { |o| options.network_exploitable = o }
  opt.on('-c', '--cve CVE-XXXX-YYYYY', 'list images vulnerable to a CVE identifier') { |o| options.cve = o }
  # --cve runs independent of other flags
end.parse!

puts "Scanning for deployed images vulnerable to #{options.cve}..." unless options.cve.nil?
vulnerable_images = []

# get Trivy output for each image (limits number of Trivy runs)
trivy_output = {}
all_images = `kubectl get pods --all-namespaces -o jsonpath="{..image}"`.split(' ').sort.uniq
all_images.each do |image|
  begin
    print "Scanning #{image}..." + ' ' * 100 + "\r"
    output = JSON.parse(`trivy --quiet --light image -f json -s #{options.severity} #{"--ignore-unfixed" unless options.patch_available.nil?} #{image}`)
    $stdout.flush
  rescue
    puts "Unable to scan #{image}. Can't access from here?"
  end
  unless output.nil?
    trivy_output.merge!({ "#{image}" => output[0] })
  end
end

puts 'Vulnerability scan complete. Munging data...' + ' ' * 100

vulns_by_namespace = {}
vulns_by_pod = {}
vulns_by_image = {}
total_count, critical_count, high_count, medium_count, low_count, unknown_count = 0, 0, 0, 0, 0, 0
trivy_output.each do |image, output|
  next if output['Vulnerabilities'].nil?

  vulns_by_image.merge!({ image => output['Vulnerabilities'].size })
  output['Vulnerabilities'].each do |vulnerability|
    total_count += 1
    critical_count += 1 if vulnerability['Severity'] == 'CRITICAL'
    high_count +=1 if vulnerability['Severity'] == 'HIGH'
    medium_count +=1 if vulnerability['Severity'] == 'MEDIUM'
    low_count +=1 if vulnerability['Severity'] == 'LOW'
    unknown_count +=1 if vulnerability['Severity'] == 'UNKNOWN'
  end
end

# the master object. observe and despair.
obj = {}
# shells out to get all the namespaces. hope you auth'd.
namespaces = `kubectl get namespaces -o jsonpath="{..name}"`.split(' ')
namespaces.each do |namespace|
  namespace_vulns = 0

  # grabs all the pods in this namespace.
  pods = `kubectl -n #{namespace} get pods --no-headers -o custom-columns=":metadata.name"`.split("\n")
  pods_object = {}
  pods.each do |pod|
    pod_vulns = 0
    # here's where we stuff images with vulnerabilities
    images_object = {}
    # grabs each unique image in this pod
    images = `kubectl -n #{namespace} get pod #{pod} -o jsonpath="{..image}"`.split(' ').sort.uniq
    images.each do |image|
      # skip if image didn't scan or no vulnerabilities found for image
      unless (trivy_output[image].nil? || trivy_output[image]['Vulnerabilities'].nil?)
        trivy_output[image]['Vulnerabilities'].each do |vuln|
          # run this crazy logic as long as we aren't in CVE mode
          if options.cve.nil?
            # count all the things if we don't care about network exploitability
            if options.network_exploitable.nil?
              namespace_vulns += 1
              pod_vulns += 1
            # if we do care, count them if they matter
            elsif (vuln['CVSS']['nvd']['V3Vector'].include?('AV:N') || vuln['CVSS']['nvd']['V2Vector'].include?('AV:N'))
              namespace_vulns += 1
              pod_vulns += 1
            # if we do care, and they don't matter, delete 'em
            else
              trivy_output[image]['Vulnerabilities'].delete(vuln)
            end
          else
            # we're in CVE mode
            if vuln['VulnerabilityID'] == options.cve
              vulnerable_images << "#{namespace}|#{pod}|#{image}"
              namespace_vulns += 1
              pod_vulns += 1
            end
          end
        end
      end
      images_object.merge!({ image => trivy_output[image] })
    end
    pods_object.merge!({ pod => images_object })
    vulns_by_pod.merge!({ "#{namespace}/#{pod}" => pod_vulns })
  end
  obj.merge!({ namespace => pods_object })
  vulns_by_namespace.merge!({ namespace => namespace_vulns })
end

### Output Section ###

if options.cve.nil?
  puts "Total Unique Vulnerabilities: #{total_count}"
  puts "  Critical Severity: #{critical_count}" if options.severity.include?('CRITICAL')
  puts "  High Severity: #{high_count}" if options.severity.include?('HIGH')
  puts "  Medium Severity: #{medium_count}" if options.severity.include?('MEDIUM')
  puts "  Low Severity: #{low_count}" if options.severity.include?('LOW')
  puts "  Unknown Severity: #{unknown_count}" if options.severity.include?('UNKNOWN')

  puts "\n\n"

  puts "Vulnerabilities by Namespace:"
  vulns_by_namespace.sort_by { |namespace, count| -count }.each do |namespace, count|
    puts "  #{namespace}: #{count}" unless count.zero?
  end

  puts "\n\n"

  puts "Vulnerabilities by Pod:"
  vulns_by_pod.sort_by { |pod, count| -count }.each do |pod, count|
    puts "  #{pod}: #{count}" unless count.zero?
  end

  puts "\n\n"

  puts "Vulnerabilities by Image:"
  vulns_by_image.sort_by { |image, count| -count }.each do |image, count|
    puts "  #{image}: #{count}" unless count.zero?
  end

  ## TODO: Vulnerabilities by Library

  puts "\n\n"

  puts "Detailed JSON written to 'trivyal_pursuit.json'"

  # gonna be a couple dozen MB, probably
  File.write('trivyal_pursuit.json', obj.to_json)
else
  if vulnerable_images.empty?
    puts "No vulnerable pods detected!"
  else
    puts "Images vulnerable to #{options.cve}:"
    puts '  NAMESPACE/POD' + ' ' * 38 + 'IMAGE'
    vulnerable_images.each do |image|
      str = image.split('|')
      # god help us if the namespace + pod name are longer than 50 characters
      puts "  #{(str[0] + '/' + str[1]).ljust(50)} #{str[2]}"
    end
  end
end
