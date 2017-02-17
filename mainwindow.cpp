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

#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QSettings>
#include <QLineEdit>


void MainWindow::writeSettings()
{
    QCoreApplication::setOrganizationName("JacksSoftware");
    QCoreApplication::setOrganizationDomain("JacksSoftware.local");
    QCoreApplication::setApplicationName("w215switcher");
    QSettings settings;
    settings.beginGroup("MainWindow");
    if ( sp->user.size() != 0 )
    {
        settings.setValue("settings/user", sp->user );
    }
    if ( sp->password.size() != 0 )
    {
        settings.setValue("settings/password", sp->password );
    }
    if ( sp->ip.size() != 0 )
    {
        settings.setValue("settings/ip", sp->ip );
    }
    settings.endGroup();
}

void MainWindow::readSettings()
{
    QCoreApplication::setOrganizationName("JacksSoftware");
    QCoreApplication::setOrganizationDomain("JacksSoftware.local");
    QCoreApplication::setApplicationName("w215switcher");

    QSettings settings;
    settings.beginGroup( "MainWindow" );
    QString user = settings.value("settings/user").toString();
    QString password = settings.value("settings/password").toString();
    QString ip = settings.value("settings/ip").toString();
    settings.endGroup();
    sp->user = user;
    sp->password = password;
    sp->ip = ip;
    sp->h_url.clear();

   // std::cout << " user is : " << sp->user.toStdString() << std::endl;

    if ( sp->user.size() != 0 )
    {
        ui->input_user->setPlaceholderText( sp->user );
    }
    if ( sp->password.size() != 0 )
    {

        ui->input_password->setEchoMode( QLineEdit::Password );
      //  ui->input_password->setPlaceholderText( sp->password );
        ui->input_password->setText( sp->password );

    }
    if ( sp->ip.size() != 0 )
    {
        ui->input_ip_address->setPlaceholderText( sp->ip );
    }
    sp->h_url = "http://" + sp->ip.toStdString() + "/HNAP1/";

}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{

    ui->setupUi(this);
    readSettings();

    sp->auth_status = sp->Authenticate();
    if ( sp->auth_status )
    {
        sp->relay_state = sp->GetRelayState();
        const QString& m_relaystate = sp->relay_state ? "On." : "Off.";
        ui->lbl_relay_state->setText( m_relaystate );
    }
    else {
        const QString& m_relaystate = "Not connected.";
        ui->lbl_relay_state->setText( m_relaystate );
    }

    const QString& m_authstate = sp->auth_status ? "Authenticated." : "Not Authenticated.";




    ui->lbl_auth_result->setText( m_authstate );

}

void MainWindow::closeEvent( QCloseEvent *event )
{
    sp->user = ui->input_user->text();
    sp->password = ui->input_password->text();
    sp->ip = ui->input_ip_address->text();
    writeSettings();

}

MainWindow::~MainWindow()
{
    delete ui;

}



void MainWindow::on_btn_switch_clicked()
{
    sp->user = ui->input_user->text();
    sp->password = ui->input_password->text();
    sp->ip = ui->input_ip_address->text();
    writeSettings();

    ui->btn_switch->setEnabled(false);

    sp->auth_status = sp->Authenticate();
    bool m_failed = false;

    QApplication::processEvents();
    if ( sp->auth_status )
    {
            std::string m_state = sp->relay_state ? "true" : "false";
            std::cout << "Relay state is: " << m_state << std::endl;

            m_failed = sp->SetRelayState( sp->relay_state );

            const QString& m_relaystate = sp->relay_state ? "On." : "Off.";
            ui->lbl_relay_state->setText( m_relaystate );

            sp->relay_state = ! sp->relay_state;
            std::cout << "Relay state is: " << m_state << std::endl;
            if ( !m_failed )
                ui->btn_switch->setText( (const QString)"Turn On" );



    }

    ui->btn_switch->setEnabled(true);

}
