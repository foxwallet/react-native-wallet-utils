require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-wallet-utils-debug"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.description  = <<-DESC
                  react-native-wallet-utils
                   DESC
  s.homepage     = "https://github.com/foxwallet/react-native-wallet-utils"
  s.license      = "Apache-2"
  s.authors      = { "foxwallet" => "dev@foxwallet.com" }
  s.platforms    = { :ios => "9.0" }
  s.source       = { :git => "https://github.com/foxwallet/react-native-wallet-utils.git", :tag => "#{s.version}" }
  s.vendored_libraries = 'ios/debug/libcore.a'
  s.vendored_frameworks = 'ios/Frameworks/GoCore.xcframework'
  s.source_files = "ios/**/*.{h,c,m,swift}"
  s.requires_arc = true

  s.dependency "React"
  # ...
  # s.dependency "..."
end

