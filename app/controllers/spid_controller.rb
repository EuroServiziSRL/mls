# -*- encoding : utf-8 -*-
require 'spid-es'
require 'openssl'
require "base64"
require "zlib"
require 'jwe'

class SpidController < ApplicationController

    include Spid::Saml::Coding
    CHIAVE = Rails.application.credentials.external_auth_api_key #usare per jwt e jwe con altre app rails es


    #GET get_metadata
    def get_metadata
        begin
            #ottengo i dati del cliente, cert e chiave e varie conf passate da portale/app esterna.
            hash_dati_cliente = authorize_request
            if hash_dati_cliente['esito'] == 'ok'
                #preparo i params per creare i settings
                params_per_settings = prepara_params(hash_dati_cliente)
                
                saml_settings = get_saml_settings(params_per_settings)
                meta = Spid::Saml::Metadata.new
                resp = {}
                resp['esito'] = 'ok'
                resp['metadata'] = meta.generate(saml_settings)
            else
                #se esito non ok, ripasso direttamente l'hash con l'errore
                resp = hash_dati_cliente
            end
        rescue => exception
            logger.error exception.message
            logger.error exception.backtrace.join("\n") 
            resp = {}
            resp['esito'] = 'ko'
            resp['msg_errore'] = exception.message
        ensure
            render json: resp
        end
        
    end

    #POST get_auth_request
    def get_auth_request
        begin
            #arriva id dell'ente, chiamo servizio di auth_hub che mi restituisce i dati del cliente
            #ottengo i dati del cliente, cert e chiave e varie conf passate da portale/app esterna.
            hash_dati_cliente = authorize_request 
            #preparo i parametri per avere i setting per fare la chiamata
            params_per_settings = prepara_params(hash_dati_cliente)
            saml_settings = get_saml_settings(params_per_settings)
            
            #create an instance of Spid::Saml::Authrequest
            request = Spid::Saml::Authrequest.new(saml_settings)
            auth_request = request.create

            #stampo la request se metto il log level debug
            #Spider.logger.debug "\n REQUEST #{auth_request.request} \n"

            # Based on the IdP metadata, select the appropriate binding 
            # and return the action to perform to the controller
            meta = Spid::Saml::Metadata.new(saml_settings)
            signature = get_signature(auth_request.uuid,auth_request.request,"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            debugger
            sso_request = meta.create_sso_request( auth_request.request, {  :RelayState   => request.uuid,
                                                                            :SigAlg       => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                                                                            :Signature    => signature } )

            #Creo oggetto da ritornare con info per traciatura e url per fare redirect
            resp = {}
            resp['esito'] = 'ok'
            resp['b64_request_comp'] = Base64.strict_encode64(Zlib::Deflate.deflate(auth_request.request))
            resp['uuid'] = auth_request.uuid
            resp['issue_instant'] = auth_request.issue_instant
            resp['sso_request'] = sso_request
        rescue => exception
            logger.error exception.message
            logger.error exception.backtrace.join("\n") 
            resp = {}
            resp['esito'] = 'ko'
            resp['msg_errore'] = exception.message
            
        ensure
            render json: resp
        end
    end


    
   


    private
    

    #arriva un hash_dati_cliente del tipo 
    # { "client"=>"78fds78sd",
    #    "secret"=>"dv87s86df8vd8v8vdhvtvehal4545sjkljb",
    #     "url_app_ext"=>"",
    #     "url_ass_cons_ext"=>"",
    #     "issuer"=>"areatest.soluzionipa.it",
    #     "org_name"=>"Area Test",
    #     "org_display_name"=>"Area Test",
    #     "org_url"=>"areatest.soluzionipa.it",
    #     "key_b64"=>"localhost.key",
    #     "cert_b64"=>"localhost.crt",
    #     "app_ext"=>false,
    #     "esito"=>"ok"}
    #verifico secret
    def authorize_request
        begin
            jwt_token = request.headers['Authorization']
            jwt_token = jwt_token.split(' ').last if jwt_token
            #chiamo auth_hub con questo client_id per avere il secret e decodificare il jwt_token
            #chiave segreta recuperata con Rails.application.credentials.external_auth_api_key
            payload = {
                'client_id' => conf_params['client_id'],
                'tipo_login' => 'spid',
                'start' => DateTime.now.new_offset(0).strftime("%d%m%Y%H%M%S")  #datetime in formato utc all'invio
            }    
            bearer_token = JsonWebToken.encode(payload, CHIAVE)
            response = HTTParty.get(File.join(Settings.url_auth_hub,"api/get_info_login_cliente"),
                :headers => { 'Authorization' => "Bearer #{bearer_token}" },
                :follow_redirects => false,
                :timeout => 500 )
            unless response.blank?
                if response['esito'] == 'ok'
                    begin
                    #arriva un jwe, devo decriptarlo
                        priv_key = OpenSSL::PKey::RSA.new(File.read(Settings.path_pkey_es))
                        info_cliente_decoded = JWE.decrypt(response['jwe'], priv_key)
                    rescue => exc
                        return { 'esito' => 'ko', 'msg_errore' => "Verifica JWE fallita: "+exc.message }
                    end
                    begin
                        hash_dati_cliente = JSON.parse(info_cliente_decoded)
                        #decodifico il jwt_token con la secret arrivata nel jwe
                        jwt_token_decoded = JsonWebToken.decode(jwt_token, hash_dati_cliente['secret'])
                    rescue => exc
                        return { 'esito' => 'ko', 'msg_errore' => exc.message }
                    rescue JWT::DecodeError => exc_jwt
                        return { 'esito' => 'ko', 'msg_errore' => "Decodifica JWT fallita: "+exc_jwt.message }
                    end
                    #controllo istante di start
                    if JsonWebToken.valid_token(jwt_token_decoded)
                        #ripasso le info arrivate dal portale se ci sono
                        hash_dati_cliente['hash_assertion_consumer'] = jwt_token_decoded['hash_assertion_consumer'] unless jwt_token_decoded['hash_assertion_consumer'].blank?
                        hash_dati_cliente['test'] = jwt_token_decoded['test'] unless jwt_token_decoded['test'].blank?
                        #scelta idp
                        hash_dati_cliente['client_id'] = conf_params['client_id']
                        hash_dati_cliente['idp'] = conf_params['idp']
                        hash_dati_cliente['esito'] = 'ok'
                        return hash_dati_cliente
                    else
                        return { 'esito' => 'ko', 'msg_errore' => "Richiesta in timeout" }
                    end
                else
                    return { 'esito' => 'ko', 'msg_errore' => response['msg_errore'] }
                end                        
            else
                return { 'esito' => 'ko', 'msg_errore' => "Errore nel recupero dei dati cliente." }
            end
        rescue => exc
            return { 'esito' => 'ko', 'msg_errore' => exc.message }
        end
    end



    #Crea la signature con metodi della gemma (vedi include Spid::Saml::Coding)
    def get_signature(relayState, request, sigAlg)
        #url encode relayState
        relayState_encoded = escape(relayState)
        #deflate e base64 della samlrequest
        deflate_request_B64 = encode(deflate(request))
        #url encode della samlrequest
        deflate_request_B64_encoded = escape(deflate_request_B64)
        #url encode della sigAlg
        sigAlg_encoded = escape(sigAlg)
        #querystring="RelayState=#{relayState_encoded}&SAMLRequest=#{deflate_request_B64_encoded}&SigAlg=#{sigAlg_encoded}"
        querystring="SAMLRequest=#{deflate_request_B64_encoded}&RelayState=#{relayState_encoded}&SigAlg=#{sigAlg_encoded}"
        #puts "**QUERYSTRING** = "+querystring
        #digest = OpenSSL::Digest::SHA1.new(querystring.strip) sha1
        digest = OpenSSL::Digest::SHA256.new(querystring.strip) #sha2 a 256
        chiave_privata = "#{Rails.root}/config/certs/key.pem" #chiave fornita da agid
        pk = OpenSSL::PKey::RSA.new File.read(chiave_privata) #chiave privata
        qssigned = pk.sign(digest,querystring.strip)
        encode(qssigned)
    end

    #passo un hash di parametri per creare i settings
    def get_saml_settings(params_settings)
        settings = Spid::Saml::Settings.new
        
        portal_url = params_settings['portal_url'] 
    
        settings.assertion_consumer_service_url     = params_settings['assertion_consumer_url'] || portal_url+'/auth/spid/assertion_consumer'
        settings.issuer                             = params_settings['issuer']
        settings.sp_cert                            = params_settings['cert_path']
        #settings.sp_external_consumer_cert          = Spider.conf.get('portal.spid.sp_external_consumer_cert') #array di path di certificati di consumer esterni
        settings.sp_private_key                     = params_settings['private_key_path'] 
        settings.single_logout_service_url          = params_settings['logout_url'] || portal_url+'/auth/spid/logout_service'
        settings.name_identifier_format             = ["urn:oasis:names:tc:SAML:2.0:nameid-format:transient"]
        settings.single_logout_destination          = params_settings['single_logout_destination']        
        settings.idp_name_qualifier                 = params_settings["idp_name_qualifier"]
        settings.destination_service_url            = params_settings['destination_service_url']
        settings.idp_sso_target_url                 = params_settings['idp_sso_target_url']
        settings.idp_metadata                   = params_settings['idp_metadata']
        settings.authn_context                      = ["urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]
        settings.skip_validation                    = params_settings['skip_validation']
        settings.requested_attribute                = ['spidCode', 'name', 'familyName', 'fiscalNumber', 'email', 'gender', 'dateOfBirth', 'placeOfBirth', 'countyOfBirth', 'idCard', 'address', 'digitalAddress', 'expirationDate', 'mobilePhone', 'ivaCode', 'registeredOffice']
        settings.metadata_signed                    = true
        settings.organization                       = params_settings['organization']
        settings.assertion_consumer_service_index   = params_settings['assertion_consumer_service_index']
        settings.attribute_consuming_service_index  = params_settings['attribute_consuming_service_index']
        #ho degli hash identificati dagli indici degli AssertionConsumerService tags nei metadata. Costruisco AssertionConsumerService e AttributeConsumingService
        settings.hash_assertion_consumer            = params_settings['hash_assertion_consumer']
        #se il campo settings.hash_assertion_consumer[indiceN][url_consumer] è vuoto, uso settings.assertion_consumer_service_url
        settings.hash_assertion_consumer.each_pair{ |index,hash_service|
            hash_service['url_consumer'] = settings.assertion_consumer_service_url if hash_service['url_consumer'].blank?
        }
        
        settings
    end

    def prepara_params(hash_dati_cliente)
        #arrivano certificato e chiave in base64, uso dei tempfile (vengono puliti dal garbage_collector)
        cert_temp_file = Tempfile.new("temp_cert_#{hash_dati_cliente['client']}")
        cert_temp_file.write(Zlib::Inflate.inflate(Base64.strict_decode64(hash_dati_cliente['cert_b64'])))
        cert_temp_file.rewind
        key_temp_file = Tempfile.new("temp_key_#{hash_dati_cliente['client']}")
        key_temp_file.write(Zlib::Inflate.inflate(Base64.strict_decode64(hash_dati_cliente['key_b64'])))
        key_temp_file.rewind

        params_per_settings = {}
        params_per_settings['issuer'] = hash_dati_cliente['issuer']
        params_per_settings['organization'] = { "org_name" => hash_dati_cliente['org_name'], 
                                                "org_display_name" => hash_dati_cliente['org_display_name'], 
                                                "org_url" => hash_dati_cliente['org_url'] }
        params_per_settings['portal_url'] = hash_dati_cliente['org_url']
        params_per_settings['cert_path'] = cert_temp_file.path
        params_per_settings['private_key_path'] = key_temp_file.path
        default_hash_assertion_consumer = {   "0" => {  'url_consumer' => '',
                                                        'external' => false,
                                                        'default' => true, 
                                                        'array_campi' => ['dateOfBirth', 'fiscalNumber', 'name', 'familyName'],
                                                        'testo' => 'User Data'
                                            } } 
        params_per_settings['hash_assertion_consumer'] = (hash_dati_cliente['hash_assertion_consumer'].blank? ? default_hash_assertion_consumer : hash_dati_cliente['hash_assertion_consumer'] )
        #se chiedo i metadata non passo idp
        unless hash_dati_cliente['idp'].blank?
            params_per_settings['destination_service_url'] =  Settings.hash_gestori_spid[hash_dati_cliente['idp']]['url_authnrequest']
            params_per_settings['idp_sso_target_url'] =  Settings.hash_gestori_spid[hash_dati_cliente['idp']]['url_authnrequest']
            params_per_settings['idp_metadata'] = Settings.hash_gestori_spid[hash_dati_cliente['idp']]['idp_metadata']
            params_per_settings['idp_name_qualifier']= Settings.hash_gestori_spid[hash_dati_cliente['idp']]['idp_name_qualifier']
        end
        #se ho richiesto l'accesso con EIDAS devo cambiare gli index 
        if hash_dati_cliente['idp'] == "eidas"
            params_per_settings['assertion_consumer_service_index'] = 100
            params_per_settings['attribute_consuming_service_index'] = 100
        else
            params_per_settings['assertion_consumer_service_index'] = 0
            params_per_settings['attribute_consuming_service_index'] = 0
        end

        params_per_settings
    end


    def conf_params
        params.permit(:client_id, :idp)
    end




end
