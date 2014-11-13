# See bottom of file for license and copyright information

package Apache::FoswikiDAVHandler;

use strict;
use warnings;

use Apache2::Const qw(ACCESS_CONF TAKE1 TAKE2);
use Apache2::Module     ();
use Apache2::RequestRec ();

use Apache::WebDAV;
our $VERSION = '$Rev: 1.0.3 $';
our $RELEASE = '%$RELEASE%';

my @directives = (
    {
        name         => 'FoswikiLocation',
        func         => __PACKAGE__ . '::FoswikiLocation',
        req_override => ACCESS_CONF,
        args_how     => TAKE1,
        errmsg       => 'Location of URI root',
    },
    {
        name         => 'FoswikiFilesysHandler',
        func         => __PACKAGE__ . '::FoswikiFilesysHandler',
        req_override => ACCESS_CONF,
        args_how     => TAKE1,
        errmsg       => 'Foswiki filesystem handler',
    },
    {
        name         => 'FoswikiDebug',
        func         => __PACKAGE__ . '::FoswikiDebug',
        req_override => ACCESS_CONF,
        args_how     => TAKE1,
        errmsg       => 'Debug switch; 1 for on, 0 for off',
    },
);

Apache2::Module::add( __PACKAGE__, \@directives );

# Directive callback
sub FoswikiLocation {
    my ( $this, $parms, $arg ) = @_;
    $this->{FoswikiLocation} = $arg;
}

# Directive callback
sub FoswikiFilesysHandler {
    my ( $this, $parms, $arg ) = @_;
    $this->{FoswikiFilesysHandler} = $arg;
}

# Directive callback
sub FoswikiDebug {
    my ( $this, $parms, $arg ) = @_;
    $this->{FoswikiDebug} = $arg;
}

our $dav;

sub handler {
    my $r = shift;

    unless ($dav) {
        my $dir_cfg = Apache2::Module::get_config( __PACKAGE__, $r->server,
            $r->per_dir_config );

        $dav = new Apache::WebDAV( $dir_cfg->{FoswikiDebug}, $dir_cfg->{FoswikiLocation} );

        my @handlers = (
            {
                path   => $dir_cfg->{FoswikiLocation},
                module => (
                    $dir_cfg->{FoswikiFilesysHandler}
                      || 'Filesys::Virtual::Foswiki'
                ),
                args => {
                    validateLogin => 0,
                    trace         => $dir_cfg->{FoswikiDebug},
                }
            }
        );

        $dav->register_handlers(@handlers);
    }
    $dav->process($r);
}

1;
__END__

=pod

Apache module for Foswiki WebDAV

httpd.conf fragment for configuring test servers:

############
## WebDAV ##
############
# TO USE BASIC AUTH:
# $ export APACHE_ARGUMENTS='-DBASIC' ; apache2ctl restart
# TO USE DIGEST AUTH:
# $ export APACHE_ARGUMENTS='-DDIGEST' ; apache2ctl restart
# TO USE NO AUTH, then:
# apache2ctl restart

PerlRequire "/var/www/foswiki/tools/WebDAVContrib_mod_perl_startup.pl"
PerlLoadModule Apache::FoswikiDAVHandler
# Foswiki DAV -
<Location "/fw_dav">
    AuthName "Foswiki"
    <IfDefine DIGEST>
        AuthType Digest
        AuthDigestDomain /dav/ http://my.server/fw_dav/
        AuthDigestProvider file
        AuthUserFile /var/www/foswiki/data/.htdigest
        <LimitExcept OPTIONS>
            require valid-user
        </LimitExcept>
    </IfDefine>
    <IfDefine BASIC>
	    AuthType Basic
  	    AuthUserFile /var/www/foswiki/data/.htpasswd
        <LimitExcept OPTIONS>
            require valid-user
        </LimitExcept>
    </IfDefine>

    SetHandler perl-script
    FoswikiFilesysHandler Filesys::Virtual::Foswiki
    FoswikiLocation /dav
    FoswikiDebug 0
    PerlHandler Apache::FoswikiDAVHandler
</Location>

<Location "/fs_dav">

    AuthName "Foswiki"
    <IfDefine DIGEST>
        AuthType Digest
        AuthDigestDomain /dav/ http://my.server/fs_dav/
        AuthDigestProvider file
        AuthUserFile /var/www/foswiki/data/.htdigest
        <LimitExcept OPTIONS>
            require valid-user
        </LimitExcept>
    </IfDefine>
    <IfDefine BASIC>
	    AuthType Basic
  	    AuthUserFile /var/www/foswiki/data/.htpasswd
        <LimitExcept OPTIONS>
            require valid-user
        </LimitExcept>
    </IfDefine>

    SetHandler perl-script
    FoswikiFilesysHandler Filesys::Virtual::PlainPlusAttrs
    FoswikiLocation /chav
    FoswikiDebug 0
    PerlHandler Apache::FoswikiDAVHandler
</Location>

Alias "/mod_dav" "/var/www/foswiki/pub"
<Directory "/var/www/foswiki/pub">

    AuthName "Foswiki"
    <IfDefine DIGEST>
        AuthType Digest
        AuthDigestDomain /dav/ http://my.server/mod_dav/
        AuthDigestProvider file
        AuthUserFile /var/www/foswiki/data/.htdigest
        <LimitExcept OPTIONS>
            require valid-user
        </LimitExcept>
    </IfDefine>
    <IfDefine BASIC>
	    AuthType Basic
  	    AuthUserFile /var/www/foswiki/data/.htpasswd
        <LimitExcept OPTIONS>
            require valid-user
        </LimitExcept>
    </IfDefine>

    Dav On

</Directory>

=cut

Copyright (C) 2008-2012 WikiRing http://wikiring.com

This program is licensed to you under the terms of the GNU General
Public License, version 2. It is distributed in the hope that it will
be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

This software cost a lot in blood, sweat and tears to develop, and
you are respectfully requested not to distribute it without purchasing
support from the authors (available from webdav@c-dot.co.uk). By working
with us you not only gain direct access to the support of some of the
most experienced Foswiki developers working on the project, but you are
also helping to make the further development of open-source Foswiki
possible.

Author: Crawford Currie http://c-dot.co.uk
