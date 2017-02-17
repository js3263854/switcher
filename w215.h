/*
    MIT License

    Copyright (c) 2017 Jack K Smith

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

*/


#ifndef W215_H
#define W215_H

#include <iostream>
#include <string>

#include <locale>


#include "pugixml.hpp"

#include <openssl/hmac.h>

#include <sstream>
#include <algorithm>
#include <string>
#include <iomanip>

#include <codecvt>

#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
#include <curlpp/Exception.hpp>


#define IP_ADDRESS "192.168.1.6"
#define URL "http://192.168.1.6/HNAP1/"
#define USER "Admin"
#define PASSWORD 111111
#define LEGACY_SET true

#define MAX_HMAC_HEX_LEN 20

class SmartPlug {

    public:
    SmartPlug( );

    std::string InitialAuthPayload();
    std::string RequestBody( std::string&, std::string& );
    std::string AuthPayLoad( const std::string& );
    std::string ControlParameters( std::string&, std::string& );

    bool SetRelayState( bool );
    bool GetRelayState( );

    bool Authenticate();

    std::string h_url;
    std::string hnap_auth;
    std::string cookie;
    std::string publickey;
    std::string loginpass;
    std::string challenge;
    std::string hexdigest;


    bool auth_status;
    bool relay_state;

    QString user;
    QString password;
    QString ip;

    /*
    std::string h_ip;
    std::string h_user;
    std::string h_password;
    */

    bool h_legacy;

    private:

    char *locale;

};

static SmartPlug * sp = new SmartPlug( );

inline bool SmartPlug::Authenticate()
{
    #ifdef DEBUG
    std::cout << "-> SmartPlug::Authenticate()" << std::endl;
    #endif
    bool retok = false;
    std::string m_payload = sp->InitialAuthPayload();
    auth_status = false;
    try
    {

        // Request public key, cookie and challenge

        using namespace curlpp;

        curlpp::Cleanup m_cleaner;
        curlpp::Easy m_request;

        std::stringstream m_result;

        std::list< std::string> m_headers;
        m_headers.push_back( "Content-Type: \"text/xml; charset=utf-8\"" );
        m_headers.push_back( "SOAPAction: \"http://purenetworks.com/HNAP1/Login\"" );


        using namespace curlpp::Options;

        m_request.setOpt( new Verbose( false ) );

        m_request.setOpt( new HttpHeader( m_headers ) );

        m_request.setOpt( new WriteStream( &m_result ) );

        m_request.setOpt( new PostFields( m_payload ) );
        m_request.setOpt( new PostFieldSize( m_payload.length() ));

        m_request.setOpt( new Url( sp->h_url.c_str() ) );

        m_request.perform();

      //  const QString& qText = m_result.str().c_str();
      //  ui->label->setText( qText );

        // Parse XML response
        pugi::xml_document m_doc;
        pugi::xml_parse_result m_parseresult = m_doc.load( m_result );

        pugi::xml_node m_nodes = m_doc.child("soap:Envelope").child("soap:Body").child("LoginResponse");

        pugi::xml_node m_challenge = m_nodes.child("Challenge");
        pugi::xml_node m_cookie = m_nodes.child("Cookie");
        pugi::xml_node m_publickey = m_nodes.child("PublicKey");

    //    std::cout << m_challenge.name() << " : " << m_challenge.child_value()<< std::endl;
    //    std::cout << m_cookie.name() << " : " << m_cookie.child_value() << std::endl;
    //    std::cout << m_publickey.name() << " : " << m_publickey.child_value() << std::endl;

        challenge = m_challenge.child_value();
        cookie = m_cookie.child_value();
        publickey = m_publickey.child_value();

        if ( !m_challenge || !m_cookie || !m_publickey )
        {
            throw "no challenge, cookie or publickey";
        }
        // Generate hash responses

        std::string m_pwd = std::to_string(PASSWORD);
        std::string m_pubkey = m_publickey.child_value();

        std::string m_nkey = m_pubkey + m_pwd;

        std::string m_chal = m_challenge.child_value();
      //  std::cout << m_nkey << std::endl;

        // Private Key
        std::string m_hexdigest;
        {
            m_hexdigest.clear();
            unsigned char* result;
            unsigned int len = MAX_HMAC_HEX_LEN;

            result = new unsigned char[ len ];

            HMAC_CTX ctx;
            HMAC_CTX_init( &ctx );

            HMAC_Init_ex( &ctx, m_nkey.c_str(), m_nkey.length(), EVP_md5(), NULL );
            HMAC_Update( &ctx, (unsigned char*)m_chal.c_str(), m_chal.length() );
            HMAC_Final( &ctx, result, &len );
            HMAC_CTX_cleanup( &ctx );

            std::stringstream m_digest;

            for ( int i = 0; i < MAX_HMAC_HEX_LEN; i++ )
            {
                m_digest << std::hex << std::setfill('0') << std::setw(2) << (int)result[i];
            }

            m_hexdigest = m_digest.str();

            m_hexdigest.erase( m_hexdigest.begin()+32,m_hexdigest.end() );

            std::transform( m_hexdigest.begin(), m_hexdigest.end(), m_hexdigest.begin(), ::toupper );

            delete[] result;

            hexdigest = m_hexdigest;

          //  std::cout << "HMAC Digest: " << m_hexdigest << " " << m_hexdigest.length() << std::endl;
        }


        // Login Password
        std::string m_loginpass;
        {
            m_loginpass.clear();
            unsigned char* result;
            unsigned int len = MAX_HMAC_HEX_LEN;
            result = new unsigned char[ len ];

            HMAC_CTX ctx;
            HMAC_CTX_init( &ctx );

            HMAC_Init_ex( &ctx, m_hexdigest.c_str(), m_hexdigest.length(), EVP_md5(), NULL );
            HMAC_Update( &ctx, (unsigned char*)m_chal.c_str(), m_chal.length() );
            HMAC_Final( &ctx, result, &len );
            HMAC_CTX_cleanup( &ctx );

            std::stringstream m_logpass;
            for ( int i = 0; i < MAX_HMAC_HEX_LEN; i++ )
            {
                m_logpass << std::hex << std::setfill('0') << std::setw(2) << (int)result[i];
            }
            m_loginpass = m_logpass.str();
            m_loginpass.erase( m_loginpass.begin()+32,m_loginpass.end() );

            std::transform( m_loginpass.begin(), m_loginpass.end(), m_loginpass.begin(), ::toupper);

            loginpass = m_loginpass;

            delete[] result;

        }
      //  std::cout << "Login Pass: " << m_loginpass << " " << m_loginpass.length() << std::endl;

        // Build response payload

        std::string m_payload_resp = sp->AuthPayLoad( m_loginpass );

        curlpp::Cleanup m_cleaner_1;
        curlpp::Easy m_request_1;

        std::stringstream m_result_1;

        std::list< std::string> m_headers_1;

        std::string m_cookie_val = m_cookie.child_value();
        std::string m_header_cookie = "Cookie: uid=" + m_cookie_val;
        std::string m_hnap_auth = "HNAP_AUTH: \"" + m_hexdigest + "\"";

        m_headers_1.push_back( "Content-Type: \"text/xml; charset=utf-8\"" );
        m_headers_1.push_back( "SOAPAction: \"http://purenetworks.com/HNAP1/Login\"" );
        m_headers_1.push_back( m_hnap_auth );
        m_headers_1.push_back( m_header_cookie );

        m_request_1.setOpt( new Verbose( true ) );

        m_request_1.setOpt( new HttpHeader( m_headers_1 ) );

        m_request_1.setOpt( new WriteStream( &m_result_1 ) );

        m_request_1.setOpt( new PostFields( m_payload_resp ) );
        m_request_1.setOpt( new PostFieldSize( m_payload_resp.length() ));

        m_request_1.setOpt( new Url( sp->h_url.c_str() ) );

        m_request_1.perform();

        // Parse login status response
        std::string m_ok = "success";
        pugi::xml_document m_doc_1;
        pugi::xml_parse_result m_parseresult_1 = m_doc_1.load( m_result_1 );

        pugi::xml_node m_nodes_1 = m_doc_1.child("soap:Envelope").child("soap:Body").child("LoginResponse");

        pugi::xml_node m_login_result = m_nodes_1.child("LoginResult");

        std::string m_login_result_val = m_login_result.child_value();

        if ( !m_login_result || m_ok.compare( m_login_result_val ) != 0 )
        {
            throw "authentication failed";
        }
        retok = true;
        auth_status = true;
      //  std::cout << m_login_result.name() << " : " << m_login_result.child_value() << std::endl;

       // const QString& qText1 = m_result_1.str().c_str();
      //  ui->label_2->setText( qText1 );

    }
    catch ( curlpp::LogicError& e )
    {
        std::cout << e.what() << std::endl;
    }
    catch ( curlpp::RuntimeError& e )
    {
        std::cout << e.what() << std::endl;
    }
    return retok;
}

inline SmartPlug::SmartPlug( )
{
    this->relay_state = false;

    this->locale = setlocale(LC_ALL, "");
}

inline std::string SmartPlug::InitialAuthPayload()
{
    #ifdef DEBUG
    std::cout << "-> SmartPlug::InitialAuthPayload()" << std::endl;
    #endif
    std::string m_xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" \
           "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" \
           "<soap:Body>\n" \
           "<Login xmlns=\"http://purenetworks.com/HNAP1/\">\n" \
           "<Action>request</Action>\n"  \
           "<Username>admin</Username>\n" \
           "<LoginPassword/>\n" \
           "<Captcha/>\n" \
           "</Login>\n" \
           "</soap:Body>\n" \
           "</soap:Envelope>\n";
    #ifdef DEBUG
    std::cout << " " << m_xml << std::endl;
    #endif
    return m_xml;
}

 inline std::string SmartPlug::AuthPayLoad( const std::string& pwd )
 {
    #ifdef DEBUG
    std::cout << "-> SmartPlug::AuthPayLoad()" << std::endl;
    #endif
    std::string user = USER;
    std::string m_xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" \
           "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
           "<soap:Body>\n"
           "<Login xmlns=\"http://purenetworks.com/HNAP1/\">\n"
           "<Action>login</Action>"
           "<Username>" + user + "</Username>\n"
           "<LoginPassword>" + pwd + "</LoginPassword>\n"
           "<Captcha/>\n"
           "</Login>\n"
           "</soap:Body>\n"
           "</soap:Envelope>\n";
     #ifdef DEBUG
     std::cout << " " << m_xml << std::endl;
     #endif
     return m_xml;

 }

 inline std::string SmartPlug::RequestBody( std::string& action, std::string& params )
 {
    #ifdef DEBUG
    std::cout << "-> SmartPlug::RequestBody()" << std::endl;
    #endif
    std::string m_xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" \
            "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" \
            "<soap:Body>\n" \
            "<" + action + " xmlns=\"http://purenetworks.com/HNAP1/\">\n" \
            "" + params + "\n" \
            "</" + action + ">\n" \
            "</soap:Body>\n" \
            "</soap:Envelope>\n";
    #ifdef DEBUG
    std::cout << " " << m_xml << std::endl;
    #endif
    return m_xml;
 }

inline std::string SmartPlug::ControlParameters( std::string& module, std::string& status )
{
    #ifdef DEBUG
    std::cout << "-> SmartPlug::ControlParameters()" << std::endl;
    #endif
    std::string m_xml = "<ModuleID>" + module + "</ModuleID><NickName>Socket 1</NickName><Description>Socket 1</Description>" \
            "<OPStatus>" + status + "</OPStatus><Controller>1</Controller>";
    #ifdef DEBUG
    std::cout << " " << m_xml << std::endl;
    #endif
    return m_xml;
}

inline bool SmartPlug::SetRelayState( bool RelayStatus )
{
    #ifdef DEBUG
    std::cout << "-> SmartPlug::SetRelayState()" << std::endl;
    #endif
    bool m_setrelaystate = false;
    // assume authenticated.
    std::string m_sockset = "SetSocketSettings";
    std::string m_sockset_params = "SetSocketSettingsResult";
    std::string m_p1 = "1";
    std::string m_p2 = RelayStatus ? "true" : "false";
    std::string m_control_params = ControlParameters( m_p1, m_p2 );
    std::string m_payload = RequestBody( m_sockset, m_control_params );

    std::stringstream m_stream;
    auto m_timestamp = round( time(NULL)/1e6 );
    m_stream << std::fixed << std::setprecision(1) << m_timestamp;

    std::string m_timestamp_str = m_stream.str();
    std::string m_action_url = "http://purenetworks.com/HNAP1/" + m_sockset;
    std::string m_auth_key_code = m_timestamp_str + "\"" + m_action_url + "\"";

    // Build request
    std::string m_auth_key;
    {
        m_auth_key.clear();
        unsigned char* result;
        unsigned int len = MAX_HMAC_HEX_LEN;
        result = new unsigned char[ len ];

        HMAC_CTX ctx;
        HMAC_CTX_init( &ctx );

        HMAC_Init_ex( &ctx, hexdigest.c_str(), hexdigest.length(), EVP_md5(), NULL );
        HMAC_Update( &ctx, (unsigned char*)m_auth_key_code.c_str(), m_auth_key_code.length() );
        HMAC_Final( &ctx, result, &len );
        HMAC_CTX_cleanup( &ctx );

        std::stringstream m_authk;
        for ( int i = 0; i < MAX_HMAC_HEX_LEN; i++ )
        {
            m_authk << std::hex << std::setfill('0') << std::setw(2) << (int)result[i];
        }
        m_auth_key = m_authk.str();
        m_auth_key.erase( m_auth_key.begin()+32,m_auth_key.end() );

        std::transform( m_auth_key.begin(), m_auth_key.end(), m_auth_key.begin(), ::toupper);

        delete[] result;

    }
    std::string m_auth_key_timestamp = m_auth_key + " " + m_timestamp_str;

    // Build soap headers

    using namespace curlpp;
    using namespace curlpp::Options;

    curlpp::Cleanup m_cleaner_1;
    curlpp::Easy m_request_1;

    std::stringstream m_result_1;

    std::list< std::string> m_headers_1;

    std::string m_header_cookie = "Cookie: uid=" + cookie;
    std::string m_hnap_auth = "HNAP_AUTH: " + m_auth_key_timestamp;

    m_headers_1.push_back( "Content-Type: \"text/xml; charset=utf-8\"" );
    m_headers_1.push_back( "SOAPAction: \"" + m_action_url + "\"" );
    m_headers_1.push_back( m_hnap_auth );
    m_headers_1.push_back( m_header_cookie );

    m_request_1.setOpt( new Verbose( true ) );

    m_request_1.setOpt( new HttpHeader( m_headers_1 ) );

    m_request_1.setOpt( new WriteStream( &m_result_1 ) );

    m_request_1.setOpt( new PostFields( m_payload ) );
    m_request_1.setOpt( new PostFieldSize( m_payload.length() ));

    m_request_1.setOpt( new Url( sp->h_url.c_str() ) );

    m_request_1.perform();



    // Parse response
    std::string m_ok = "OK";
    pugi::xml_document m_doc_1;
    pugi::xml_parse_result m_parseresult_1 = m_doc_1.load( m_result_1 );

    pugi::xml_node m_nodes_1 = m_doc_1.child("soap:Envelope").child("soap:Body").child("SetSocketSettingsResponse");

    pugi::xml_node m_socket_settings_res = m_nodes_1.child("SetSocketSettingsResult");

    std::string m_socket_settings_res_val = m_socket_settings_res.child_value();

    std::cout << m_socket_settings_res_val << std::endl;

    #ifdef DEBUG
    std::cout << " Payload: " << m_payload << std::endl;
    std::cout << " Response: " << m_socket_settings_res.name() << " : " << m_socket_settings_res_val << std::endl;
    #endif

    if ( !m_socket_settings_res || m_ok.compare( m_socket_settings_res_val ) != 0 )
    {
        throw "set operation failed";
    }
    else
    {
        m_setrelaystate = true;
    }

    return m_setrelaystate;
}

inline bool SmartPlug::GetRelayState( )
{
    // assume authenticated.
    std::string m_sockset = "GetSocketSettings";

    std::string m_module_id = "<ModuleID>1</ModuleID>";

    std::string m_op_status = "OPStatus";

    std::string m_payload = RequestBody( m_sockset, m_op_status );

    std::stringstream m_stream;
    auto m_timestamp = round( time(NULL)/1e6 );
    m_stream << std::fixed << std::setprecision(1) << m_timestamp;

    std::string m_timestamp_str = m_stream.str();
    std::string m_action_url = "http://purenetworks.com/HNAP1/" + m_sockset;
    std::string m_auth_key_code = m_timestamp_str + "\"" + m_action_url + "\"";

    // Build request
    std::string m_auth_key;
    {
        m_auth_key.clear();
        unsigned char* result;
        unsigned int len = MAX_HMAC_HEX_LEN;
        result = new unsigned char[ len ];

        HMAC_CTX ctx;
        HMAC_CTX_init( &ctx );

        HMAC_Init_ex( &ctx, hexdigest.c_str(), hexdigest.length(), EVP_md5(), NULL );
        HMAC_Update( &ctx, (unsigned char*)m_auth_key_code.c_str(), m_auth_key_code.length() );
        HMAC_Final( &ctx, result, &len );
        HMAC_CTX_cleanup( &ctx );

        std::stringstream m_authk;
        for ( int i = 0; i < MAX_HMAC_HEX_LEN; i++ )
        {
            m_authk << std::hex << std::setfill('0') << std::setw(2) << (int)result[i];
        }
        m_auth_key = m_authk.str();
        m_auth_key.erase( m_auth_key.begin()+32,m_auth_key.end() );

        std::transform( m_auth_key.begin(), m_auth_key.end(), m_auth_key.begin(), ::toupper);

        delete[] result;

    }
    std::string m_auth_key_timestamp = m_auth_key + " " + m_timestamp_str;

    // Build soap headers

    using namespace curlpp;
    using namespace curlpp::Options;

    curlpp::Cleanup m_cleaner_1;
    curlpp::Easy m_request_1;

    std::stringstream m_result_1;

    std::list< std::string> m_headers_1;

    std::string m_header_cookie = "Cookie: uid=" + cookie;
    std::string m_hnap_auth = "HNAP_AUTH: " + m_auth_key_timestamp;

    m_headers_1.push_back( "Content-Type: \"text/xml; charset=utf-8\"" );
    m_headers_1.push_back( "SOAPAction: \"" + m_action_url + "\"" );
    m_headers_1.push_back( m_hnap_auth );
    m_headers_1.push_back( m_header_cookie );

    m_request_1.setOpt( new Verbose( true ) );

    m_request_1.setOpt( new HttpHeader( m_headers_1 ) );

    m_request_1.setOpt( new WriteStream( &m_result_1 ) );

    m_request_1.setOpt( new PostFields( m_payload ) );
    m_request_1.setOpt( new PostFieldSize( m_payload.length() ));

    m_request_1.setOpt( new Url( sp->h_url.c_str() ) );

    m_request_1.perform();

   // std::cout << m_result_1.str() << std::endl;

    // Parse response
    std::string m_ok = "OK";
    pugi::xml_document m_doc_1;
    pugi::xml_parse_result m_parseresult_1 = m_doc_1.load( m_result_1 );

    pugi::xml_node m_nodes_1 = m_doc_1.child("soap:Envelope").child("soap:Body").child("GetSocketSettingsResponse").child("SocketInfoList").child("SocketInfo");

    pugi::xml_node m_socket_settings_res = m_nodes_1.child("OPStatus");

    std::string m_socket_settings_res_val = m_socket_settings_res.child_value();

   // std::cout << m_socket_settings_res_val << std::endl;

    if ( !m_socket_settings_res )
    {
        throw "get operation failed";
    }

    relay_state = m_socket_settings_res_val.compare("false") == 0 ? true : false;
    return relay_state;
}



#endif // W215_H
