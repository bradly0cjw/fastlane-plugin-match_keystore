require 'fastlane/action'
require 'fileutils'
require 'os'
require 'json'
require 'openssl'
require 'digest'
require 'open3'
require_relative '../helper/match_keystore_helper'

module Fastlane
  module Actions
    module SharedValues
      MATCH_KEYSTORE_PATH = :MATCH_KEYSTORE_PATH
      MATCH_KEYSTORE_ALIAS_NAME = :MATCH_KEYSTORE_ALIAS_NAME
      MATCH_KEYSTORE_APK_SIGNED = :MATCH_KEYSTORE_APK_SIGNED
      MATCH_KEYSTORE_AAB_SIGNED = :MATCH_KEYSTORE_AAB_SIGNED
      MATCH_KEYSTORE_PASSWORD = :MATCH_KEYSTORE_PASSWORD
      MATCH_KEYSTORE_ALIAS_PASSWORD = :MATCH_KEYSTORE_ALIAS_PASSWORD
    end

    class MatchKeystoreAction < Action

      KEY_VERSION = "2"
      CIPHER_ALGO = 'aes-256-cbc'
      PBKDF2_ITER = 10_000
      PBKDF2_DIGEST = 'sha256'
      SALT_HEADER = "Salted__"

      def self.run_command(*args)
        output, status = Open3.capture2e(*args)
        unless status.success?
          UI.important("Command failed (exit #{status.exitstatus}): #{args.join(' ')}")
        end
        output
      end

      def self.tool_executable(build_tools_path, tool_name)
        if OS.windows?
          File.join(build_tools_path, "#{tool_name}.bat")
        else
          File.join(build_tools_path, tool_name)
        end
      end

      def self.to_md5(value)
        hash_value = Digest::MD5.hexdigest value
        hash_value
      end

      def self.sha512(value)
        hash_value = Digest::SHA512.hexdigest value
        hash_value
      end

      def self.load_json(json_path)
        file = File.read(json_path)
        data_hash = JSON.parse(file)
        data_hash
      end

      def self.load_properties(properties_filename)
        properties = {}
        File.open(properties_filename, 'r:utf-8') do |properties_file|
          properties_file.read.encode('UTF-8', invalid: :replace, undef: :replace).each_line do |line|
            line.strip!
            if (line[0] != ?# and line[0] != ?=)
              i = line.index('=')
              if (i)
                properties[line[0..i - 1].strip] = line[i + 1..-1].strip
              else
                properties[line] = ''
              end
            end
          end
        end
        properties
      end

      def self.get_android_home
        ENV['ANDROID_HOME'].to_s.strip
      end

      def self.get_build_tools_version(targeted_version)
        path = self.get_build_tools(targeted_version)
        version = File.basename(path.chomp('/').chomp('\\'))
        version
      end

      def self.get_build_tools(targeted_version)
        android_home = self.get_android_home()
        build_tools_root = File.join(android_home, 'build-tools')

        build_tools_path = ""
        if !targeted_version.to_s.strip.empty?
          build_tools_path = File.join(build_tools_root, targeted_version, '')
        end

        if !File.directory?(build_tools_path)
          sub_dirs = Dir.glob(File.join(build_tools_root, '*', ''))
          build_tools_last_version = ''
          for sub_dir in sub_dirs
            build_tools_last_version = sub_dir
          end
          build_tools_path = build_tools_last_version
        end

        build_tools_path
      end


      def self.gen_key(key_path, password, compat_key)
        FileUtils.rm_f(key_path)
        shaValue = self.sha512(password)
        # Backward-compatibility
        if compat_key == "1"
          shaValue = Digest::SHA512.hexdigest("#{password}\n")
        end
        File.binwrite(key_path, shaValue + "\n")
      end

      def self.encrypt_file(clear_file, encrypt_file, key_path)
        FileUtils.rm_f(encrypt_file)
        password = File.binread(key_path).chomp("\n")
        plaintext = File.binread(clear_file)

        salt = OpenSSL::Random.random_bytes(8)
        cipher = OpenSSL::Cipher.new(CIPHER_ALGO)
        key_iv = OpenSSL::PKCS5.pbkdf2_hmac(
          password, salt, PBKDF2_ITER,
          cipher.key_len + cipher.iv_len, PBKDF2_DIGEST
        )
        cipher.encrypt
        cipher.key = key_iv[0, cipher.key_len]
        cipher.iv  = key_iv[cipher.key_len, cipher.iv_len]

        ciphertext = cipher.update(plaintext) + cipher.final
        File.binwrite(encrypt_file, SALT_HEADER + salt + ciphertext)
      end

      def self.decrypt_file(encrypt_file, clear_file, key_path)
        FileUtils.rm_f(clear_file)
        password = File.binread(key_path).chomp("\n")
        data = File.binread(encrypt_file)

        unless data[0, 8] == SALT_HEADER
          raise "Decryption failed: missing salt header. " \
                "Ensure your match_secret is correct and the encrypted file is not corrupted."
        end
        salt = data[8, 8]
        ciphertext = data[16..-1]

        cipher = OpenSSL::Cipher.new(CIPHER_ALGO)
        key_iv = OpenSSL::PKCS5.pbkdf2_hmac(
          password, salt, PBKDF2_ITER,
          cipher.key_len + cipher.iv_len, PBKDF2_DIGEST
        )
        cipher.decrypt
        cipher.key = key_iv[0, cipher.key_len]
        cipher.iv  = key_iv[cipher.key_len, cipher.iv_len]

        begin
          plaintext = cipher.update(ciphertext) + cipher.final
        rescue OpenSSL::Cipher::CipherError
          raise "Decryption failed. " \
                "Ensure your match_secret is correct and the encrypted file is not corrupted."
        end
        File.binwrite(clear_file, plaintext)
      end

      def self.assert_equals(test_name, excepted, value)
        puts "Unit Test: #{test_name}"
        if value != excepted
          puts " - Excepted: #{excepted}"
          puts " - Returned: #{value}"
          raise "Unit Test - #{test_name} error!"
        else
          puts " - OK"
        end
      end

      def self.test_security

        # Clear temp files
        temp_dir = File.join(Dir.pwd, 'temp')
        FileUtils.rm_rf(temp_dir)
        Dir.mkdir(temp_dir)

        fakeValue = "4esfsf4dsfds!efs5ZDOJF"
        # Check MD5
        md5value = self.to_md5(fakeValue)
        excepted = "1c815cd208fe08076c9e7b6595d121d1"
        self.assert_equals("MD5", excepted, md5value)

        # Check SHA-512
        shaValue = self.sha512(fakeValue)
        excepted = "cc6a7b0d89cc61c053f7018a305672bdb82bc07e5015f64bb063d9662be4ec81ec8afa819b009de266482b6bd56b7068def2524c32f5b5d4d9db49ee4578499d"
        self.assert_equals("SHA-512", excepted, shaValue)

        # Check SHA-512-File
        key_path = File.join(Dir.pwd, 'temp', 'key.txt')
        self.gen_key(key_path, fakeValue, false)
        shaValue = self.get_file_content(key_path).strip!
        excepted = "cc6a7b0d89cc61c053f7018a305672bdb82bc07e5015f64bb063d9662be4ec81ec8afa819b009de266482b6bd56b7068def2524c32f5b5d4d9db49ee4578499d"
        self.assert_equals("SHA-512-File", excepted, shaValue)

        # Encrypt then decrypt round-trip
        clear_file = File.join(Dir.pwd, 'temp', 'clear.txt')
        encrypted_file = File.join(Dir.pwd, 'temp', 'encrypted.txt')
        decrypted_file = File.join(Dir.pwd, 'temp', 'decrypted.txt')
        self.content_to_file(clear_file, fakeValue)
        self.encrypt_file(clear_file, encrypted_file, key_path)
        result = File.file?(encrypted_file) && File.size(encrypted_file) > 10
        self.assert_equals("Encrypt", true, result)

        self.decrypt_file(encrypted_file, decrypted_file, key_path)
        decrypted = self.get_file_content(decrypted_file).strip!
        self.assert_equals("Decrypt-RoundTrip", fakeValue, decrypted)

      end

      def self.sign_apk(apk_path, keystore_path, key_password, alias_name, alias_password, zip_align, version_targeted)

        build_tools_path = self.get_build_tools(version_targeted)
        UI.message("Build-tools path: #{build_tools_path}")

        # https://developer.android.com/studio/command-line/apksigner
        apk_path_signed = apk_path.gsub(".apk", "-signed.apk")
        apk_path_signed = apk_path_signed.gsub("unsigned", "")
        apk_path_signed = apk_path_signed.gsub("--", "-")
        FileUtils.rm_f(apk_path_signed)

        UI.message("Signing APK (input): #{apk_path}")
        apksigner_opts = []
        build_tools_version = self.get_build_tools_version(version_targeted)
        UI.message("Build-tools version: #{build_tools_version}")
        if Gem::Version.new(build_tools_version) >= Gem::Version.new('30')
          apksigner_opts = ["--v4-signing-enabled", "false"]
        end
        apksigner = self.tool_executable(build_tools_path, "apksigner")
        output = run_command(apksigner, "sign",
                             "--ks", keystore_path,
                             "--ks-key-alias", alias_name,
                             "--ks-pass", "pass:#{key_password}",
                             "--key-pass", "pass:#{alias_password}",
                             "--v1-signing-enabled", "true",
                             "--v2-signing-enabled", "true",
                             *apksigner_opts,
                             "--out", apk_path_signed,
                             apk_path)
        puts ""
        puts output

        UI.message("Verifing APK signature (output): #{apk_path_signed}")
        output = run_command(apksigner, "verify", apk_path_signed)
        puts ""
        puts output


        # https://developer.android.com/studio/command-line/zipalign
        if zip_align != false
          apk_path_aligned = apk_path_signed.gsub(".apk", "-aligned.apk")
          FileUtils.rm_f(apk_path_aligned)
          UI.message("Aligning APK (zipalign): #{apk_path_signed}")
          zipalign = self.tool_executable(build_tools_path, "zipalign")
          output = run_command(zipalign, "-v", "4", apk_path_signed, apk_path_aligned)
          puts ""
          puts output

          if !File.file?(apk_path_aligned)
            raise "Aligned APK not exists!"
          end

          FileUtils.rm_f(apk_path_signed)
          apk_path_signed = apk_path_aligned

        else
          UI.message("No zip align - deactivated via parameter!")
        end

        apk_path_signed
      end

      def self.sign_aab(aab_path, keystore_path, key_password, alias_name, alias_password)

        aab_path_signed = aab_path.gsub('.aab', '-signed.aab')
        aab_path_signed = aab_path_signed.gsub('unsigned', '')
        aab_path_signed = aab_path_signed.gsub('--', '-')
        FileUtils.rm_f(aab_path_signed)

        UI.message("Signing AAB (input): #{aab_path}")
        output = run_command("jarsigner",
                             "-keystore", keystore_path,
                             "-storepass", key_password,
                             "-keypass", alias_password,
                             "-signedjar", aab_path_signed,
                             aab_path,
                             alias_name)
        puts ""
        puts output

        aab_path_signed
      end

      def self.resolve_dir(path)
        if !File.directory?(path)
          path = File.join(Dir.pwd, path)
        end
        path
      end

      def self.resolve_file(path)
        if !File.file?(path)
          path = File.join(Dir.pwd, path)
        end
        path
      end

      def self.content_to_file(file_path, content)
        File.write(file_path, content + "\n")
      end

      def self.get_file_content(file_path)
        data = File.read(file_path)
        data
      end

      def self.resolve_aab_path(aab_path)

        # Set default AAB path if not set:
        if aab_path.to_s.strip.empty?
          return nil
        end

        if !aab_path.to_s.end_with?('.aab')

          aab_path = self.resolve_dir(aab_path)

          pattern = File.join(aab_path, '*.aab')
          files = Dir[pattern]

          for file in files
            if file.to_s.end_with?('.aab') && !file.to_s.end_with?("-signed.aab")
              apk_path = file
              break
            end
          end

        else
          aab_path = self.resolve_file(aab_path)
        end

        aab_path
      end

      def self.resolve_apk_path(apk_path)

        # Set default APK path if not set:
        if apk_path.to_s.strip.empty?
          return nil
        end

        if !apk_path.to_s.end_with?(".apk")

          apk_path = self.resolve_dir(apk_path)

          pattern = File.join(apk_path, '*.apk')
          files = Dir[pattern]

          for file in files
            if file.to_s.end_with?(".apk") && !file.to_s.end_with?("-signed.apk")
              apk_path = file
              break
            end
          end

        else
          apk_path = self.resolve_file(apk_path)
        end

        apk_path
      end

      def self.prompt2(params)
        # UI.message("prompt2: #{params[:value]}")
        if params[:value].to_s.empty?
          return_value = other_action.prompt(text: params[:text], secure_text: params[:secure_text], ci_input: params[:ci_input])
        else
          return_value = params[:value]
        end
        return_value
      end

      def self.run(params)

        # Get input parameters:
        git_url = params[:git_url]
        package_name = params[:package_name]
        apk_path = params[:apk_path]
        aab_path = params[:aab_path]
        existing_keystore = params[:existing_keystore]
        match_secret = params[:match_secret]
        override_keystore = params[:override_keystore]
        keystore_data = params[:keystore_data]
        clear_keystore = params[:clear_keystore]
        unit_test = params[:unit_test]
        build_tools_version = params[:build_tools_version]
        zip_align = params[:zip_align]
        compat_key = params[:compat_key]
        skip_signing = params[:skip_signing]

        # Test OpenSSL/LibreSSL
        if unit_test
          result_test = self.test_security
          exit!
        end

        # Init constants:
        keystore_name = 'keystore.jks'
        properties_name = 'keystore.properties'
        keystore_info_name = 'keystore.txt'
        properties_encrypt_name = 'keystore.properties.enc'

        # Check Android Home env:
        android_home = self.get_android_home()
        UI.message("Android SDK: #{android_home}")
        if android_home.to_s.strip.empty?
          raise "The environment variable ANDROID_HOME is not defined, or Android SDK is not installed!"
        end

        # Check is backward-compatibility is required:
        if !compat_key.to_s.strip.empty?
          UI.message("Compatiblity version: #{compat_key}")
        end

        # Init working local directory:
        dir_name = File.join(Dir.home, '.match_keystore')
        unless File.directory?(dir_name)
          UI.message("Creating '.match_keystore' working directory...")
          FileUtils.mkdir_p(dir_name)
        end

        # Init 'security password' for AES encryption:
        if compat_key == "1"
          key_name = "#{self.to_md5(git_url)}.hex"
        else
          key_name = "#{self.to_md5(git_url)}-#{self::KEY_VERSION}.hex"
        end
        key_path = File.join(dir_name, key_name)
        # UI.message(key_path)
        if !File.file?(key_path)
          security_password = self.prompt2(text: "Security password: ", secure_text: true, value: match_secret)
          if security_password.to_s.strip.empty?
            raise "Security password is not defined! Please use 'match_secret' parameter for CI."
          end
          UI.message "Generating security key '#{key_name}'..."
          self.gen_key(key_path, security_password, compat_key)
        end

        # Check is 'security password' is well initialized:
        tmpkey = self.get_file_content(key_path).strip
        if tmpkey.length == 128
          UI.message "Security key '#{key_name}' initialized"
        else
          raise "The security key '#{key_name}' is malformed, or not initialized!"
        end

        # Clear repo Keystore (local) - mostly for testing:
        repo_dir = File.join(dir_name, self.to_md5(git_url))
        if clear_keystore && File.directory?(repo_dir)
          FileUtils.rm_rf(repo_dir)
          UI.message("Local repo keystore (#{repo_dir}) directory deleted!")
        end

        # Create repo directory to sync remote Keystores repository:
        unless File.directory?(repo_dir)
          UI.message("Creating 'repo' directory...")
          FileUtils.mkdir_p(repo_dir)
        end

        # Check if package name defined:
        if package_name.to_s.strip.empty?
          raise "Package name is not defined!"
        end

        # Define paths:
        keystoreAppDir = File.join(repo_dir, package_name)
        keystore_path = File.join(keystoreAppDir, keystore_name)
        properties_path = File.join(keystoreAppDir, properties_name)
        properties_encrypt_path = File.join(keystoreAppDir, properties_encrypt_name)

        # Cloning/pulling GIT remote repository:
        gitDir = File.join(repo_dir, '.git')
        if !File.directory?(gitDir)
          UI.message("Cloning remote Keystores repository...")
          run_command("git", "clone", git_url, repo_dir)
        else
          UI.message("Pulling remote Keystores repository...")
          run_command("git", "-C", repo_dir, "pull")
        end

        # Ensure .gitattributes marks binary files to prevent autocrlf corruption:
        gitattributes_path = File.join(repo_dir, '.gitattributes')
        if !File.file?(gitattributes_path)
          File.binwrite(gitattributes_path, "*.enc binary\n*.jks binary\n")
        end

        # Load parameters from JSON for CI or Unit Tests:
        if keystore_data != nil && File.file?(keystore_data)
          data_json = self.load_json(keystore_data)
          data_key_password = data_json['key_password']
          data_alias_name = data_json['alias_name']
          data_alias_password = data_json['alias_password']
          data_full_name = data_json['full_name']
          data_org_unit = data_json['org_unit']
          data_org = data_json['org']
          data_city_locality = data_json['city_locality']
          data_state_province = data_json['state_province']
          data_country = data_json['country']
        end

        # Create keystore with command
        override_keystore = !existing_keystore.to_s.strip.empty? && File.file?(existing_keystore)
        UI.message("Existing Keystore: #{existing_keystore}")
        if !File.file?(keystore_path) || override_keystore

          if File.file?(keystore_path)
            FileUtils.remove_dir(keystore_path)
          end

          # Ensure the keystore app directory exists
          FileUtils.mkdir_p(keystoreAppDir)

          key_password = self.prompt2(text: "Keystore Password: ", value: data_key_password)
          if key_password.to_s.strip.empty?
            raise "Keystore Password is not definined!"
          end
          alias_name = self.prompt2(text: "Keystore Alias name: ", value: data_alias_name)
          if alias_name.to_s.strip.empty?
            raise "Keystore Alias name is not definined!"
          end
          alias_password = self.prompt2(text: "Keystore Alias password: ", value: data_alias_password)
          if alias_password.to_s.strip.empty?
            raise "Keystore Alias password is not definined!"
          end

          # https://developer.android.com/studio/publish/app-signing
          if existing_keystore.to_s.strip.empty? || !File.file?(existing_keystore)
            UI.message("Generating Android Keystore...")

            full_name = self.prompt2(text: "Certificate First and Last Name: ", value: data_full_name)
            org_unit = self.prompt2(text: "Certificate Organisation Unit: ", value: data_org_unit)
            org = self.prompt2(text: "Certificate Organisation: ", value: data_org)
            city_locality = self.prompt2(text: "Certificate City or Locality: ", value: data_city_locality)
            state_province = self.prompt2(text: "Certificate State or Province: ", value: data_state_province)
            country = self.prompt2(text: "Certificate Country Code (XX): ", value: data_country)

            dname = "CN=#{full_name}, OU=#{org_unit}, O=#{org}, L=#{city_locality}, S=#{state_province}, C=#{country}"
            run_command("keytool", "-genkey", "-v",
                        "-keystore", keystore_path,
                        "-alias", alias_name,
                        "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                        "-storepass", alias_password,
                        "-keypass", key_password,
                        "-dname", dname)
          else
            UI.message("Copy existing keystore to match_keystore repository...")
            FileUtils.cp(existing_keystore, keystore_path)
          end

          UI.message("Generating Keystore properties...")

          if File.file?(properties_path)
            FileUtils.remove_dir(properties_path)
          end

          # Build URL:
          store_file = git_url + '/' + package_name + '/' + keystore_name

          out_file = File.new(properties_path, "w")
          out_file.puts("keyFile=#{store_file}")
          out_file.puts("keyPassword=#{key_password}")
          out_file.puts("aliasName=#{alias_name}")
          out_file.puts("aliasPassword=#{alias_password}")
          out_file.close

          self.encrypt_file(properties_path, properties_encrypt_path, key_path)
          File.delete(properties_path)

          # Print Keystore data in repo:
          keystore_info_path = File.join(keystoreAppDir, keystore_info_name)
          output = run_command("keytool", "-list", "-v",
                               "-keystore", keystore_path,
                               "-storepass", key_password)
          File.write(keystore_info_path, output)

          UI.message("Upload new Keystore to remote repository...")
          puts ''
          run_command("git", "-C", repo_dir, "add", ".")
          run_command("git", "-C", repo_dir, "commit", "-m", "[ADD] Keystore for app '#{package_name}'.")
          run_command("git", "-C", repo_dir, "push")
          puts ''

        else
          UI.message "Keystore file already exists, continue..."

          self.decrypt_file(properties_encrypt_path, properties_path, key_path)

          properties = self.load_properties(properties_path)
          key_password = properties['keyPassword']
          alias_name = properties['aliasName']
          alias_password = properties['aliasPassword']

          File.delete(properties_path)
        end

        # Prepare context shared values for next lanes:
        Actions.lane_context[SharedValues::MATCH_KEYSTORE_PATH] = keystore_path
        Actions.lane_context[SharedValues::MATCH_KEYSTORE_ALIAS_NAME] = alias_name
        Actions.lane_context[SharedValues::MATCH_KEYSTORE_PASSWORD] = key_password
        Actions.lane_context[SharedValues::MATCH_KEYSTORE_ALIAS_PASSWORD] = alias_password

        # Set Environment Variables for easy access in other tools (e.g. Flutter/Gradle)
        ENV['MATCH_KEYSTORE_PATH'] = keystore_path
        ENV['MATCH_KEYSTORE_ALIAS_NAME'] = alias_name
        ENV['MATCH_KEYSTORE_PASSWORD'] = key_password
        ENV['MATCH_KEYSTORE_ALIAS_PASSWORD'] = alias_password

        # Sign APK:
        if !skip_signing && !apk_path.to_s.strip.empty?
        
          # Resolve path to the APK to sign:
          apk_path = self.resolve_apk_path(apk_path)

          if apk_path && File.file?(apk_path) && File.file?(keystore_path)

            UI.message("APK to sign: " + apk_path)
            UI.message("Signing the APK...")
            puts ''
            output_signed_apk = self.sign_apk(
              apk_path,
              keystore_path,
              key_password,
              alias_name,
              alias_password,
              zip_align, # Zip align
              build_tools_version # Buil-tools version
            )
            puts ''
            
            # Prepare contect shared values for next lanes:
            Actions.lane_context[SharedValues::MATCH_KEYSTORE_APK_SIGNED] = output_signed_apk
            return output_signed_apk
          else
            UI.important("APK file not found or invalid: #{apk_path}")
          end 
        end

        # Sign AAB
        if !skip_signing && !aab_path.to_s.strip.empty?

          # Resolve path to the AAB to sign:
          aab_path = self.resolve_aab_path(aab_path)

          if aab_path && File.file?(aab_path) && File.file?(keystore_path)

            UI.message('AAB to sign: '+ aab_path)
            UI.message("Signing the AAB...")
            puts ''
            output_signed_aab = self.sign_aab(
              aab_path,
              keystore_path,
              key_password,
              alias_name,
              alias_password
            )
            puts ''

            # Prepare contect shared values for next lanes:
            Actions.lane_context[SharedValues::MATCH_KEYSTORE_AAB_SIGNED] = output_signed_aab
            return output_signed_aab
          else
            UI.important("AAB file not found or invalid: #{aab_path}")
          end 
        end

        UI.message("No APK or AAB file to sign, or signing skipped.")
        keystore_path
      end

      def self.description
        "Easily sync your Android keystores across your team"
      end

      def self.authors
        ["Christopher NEY", "Simon Scherzinger"]
      end

      def self.return_value
        "Prepare Keystore local path, alias name, and passwords for the specified App."
      end

      def self.output
        [
          ['MATCH_KEYSTORE_PATH', 'File path of the Keystore fot the App.'],
          ['MATCH_KEYSTORE_ALIAS_NAME', 'Keystore Alias Name.'],
          ['MATCH_KEYSTORE_PASSWORD', 'Keystore Password.'],
          ['MATCH_KEYSTORE_ALIAS_PASSWORD', 'Keystore Alias Password.'],
          ['MATCH_KEYSTORE_APK_SIGNED', 'Path of the signed APK.'],
          ['MATCH_KEYSTORE_AAB_SIGNED', 'Path of the signed AAB.']
        ]
      end

      def self.details
        # Optional:
        "This way, your entire team can use the same account and have one code signing identity without any manual work or confusion."
      end

      def self.available_options
        [
          FastlaneCore::ConfigItem.new(key: :git_url,
                                   env_name: "MATCH_KEYSTORE_GIT_URL",
                                description: "The URL of the Git repository (Github, BitBucket...)",
                                   optional: false,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :package_name,
                                   env_name: "MATCH_KEYSTORE_PACKAGE_NAME",
                                description: "The package name of the App",
                                   optional: false,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :apk_path,
                                   env_name: "MATCH_KEYSTORE_APK_PATH",
                                description: "Path of the APK file to sign",
                                   optional: true,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :aab_path,
                                   env_name: "MATCH_KEYSTORE_AAB_PATH",
                                description: "Path of the AAB file to sign",
                                   optional: true,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :match_secret,
                                   env_name: "MATCH_KEYSTORE_SECRET",
                                description: "Secret to decrypt keystore.properties file (CI)",
                                   optional: true,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :existing_keystore,
                                   env_name: "MATCH_KEYSTORE_EXISTING",
                                description: "Path of an existing Keystore",
                                   optional: true,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :override_keystore,
                                   env_name: "MATCH_KEYSTORE_OVERRIDE",
                                description: "Override an existing Keystore (false by default)",
                                   optional: true,
                                       type: Boolean),
          FastlaneCore::ConfigItem.new(key: :keystore_data,
                                   env_name: "MATCH_KEYSTORE_JSON_PATH",
                                description: "Required data to import an existing keystore, or create a new one",
                                   optional: true,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :build_tools_version,
                                   env_name: "MATCH_KEYSTORE_BUILD_TOOLS_VERSION",
                                description: "Set built-tools version (by default latest available on machine)",
                                   optional: true,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :zip_align,
                                   env_name: "MATCH_KEYSTORE_ZIPALIGN",
                                description: "Define if plugin will run zipalign on APK before sign it (true by default)",
                                   optional: true,
                                       type: Boolean),
          FastlaneCore::ConfigItem.new(key: :compat_key,
                                   env_name: "MATCH_KEYSTORE_COMPAT_KEY",
                                description: "Define the compatibility key version used on local machine (nil by default)",
                                   optional: true,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :clear_keystore,
                                   env_name: "MATCH_KEYSTORE_CLEAR",
                                description: "Clear the local keystore (false by default)",
                                   optional: true,
                                       type: Boolean),
          FastlaneCore::ConfigItem.new(key: :unit_test,
                                   env_name: "MATCH_KEYSTORE_UNIT_TESTS",
                                description: "launch Unit Tests (false by default)",
                                   optional: true,
                                       type: Boolean),
          FastlaneCore::ConfigItem.new(key: :skip_signing,
                                   env_name: "MATCH_KEYSTORE_SKIP_SIGNING",
                                description: "Skip signing the APK or AAB (false by default)",
                                   optional: true,
                                       type: Boolean,
                              default_value: false)
        ]
      end

      def self.is_supported?(platform)
        # Adjust this if your plugin only works for a particular platform (iOS vs. Android, for example)
        # See: https://docs.fastlane.tools/advanced/#control-configuration-by-lane-and-by-platform
        [:android].include?(platform)
      end
    end
  end
end