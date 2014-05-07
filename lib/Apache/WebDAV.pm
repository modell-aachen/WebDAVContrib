# See bottom of file for license, copyright, and documentation
package Apache::WebDAV;

# Unless otherwise indicated, section references in comments e.g. (8.1.3)
# relate to http://www.webdav.org/specs/rfc2518.html

use strict;
use warnings;

our $VERSION = '2.0.1';
our $RELEASE = '%$TRACKINGCODE%';

use Apache2::Const qw(:common :http);
use Apache2::Access                    ();
use Apache2::Directive                 ();
use Apache2::RequestIO                 ();
use Apache2::RequestUtil               ();
use APR::Table                         ();
use File::Find::Rule::Filesys::Virtual ();
use Encode                             ();
use URI                                ();
use URI::Escape                        ();
use XML::LibXML 1.64 ();
use APR::UUID ();
use POSIX qw(:errno_h);

our $XMLParser;
our $filesys;
our $outdoc;
our $statCache;

our @ISOMONTH = (
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
);

our @WEEKDAY = ( 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' );

# methods defined by WebDAV. Not all of these are implemented.
my @METHODS = qw( COPY DELETE GET HEAD MKCOL MOVE OPTIONS POST PROPFIND
  PUT PROPPATCH LOCK UNLOCK );

# The list of default properties
my %default_props = (
    '{DAV:}creationdate' => 1,

    # '{DAV:}displayname' => 1,
    # '{DAV:}getcontentlanguage' => 1,
    '{DAV:}getcontentlength' => 1,
    '{DAV:}getcontenttype'   => 1,
    '{DAV:}getetag'          => 1,
    '{DAV:}getlastmodified'  => 1,
    '{DAV:}lockdiscovery'    => 1,
    '{DAV:}resourcetype'     => 1,
    '{DAV:}supportedlock'    => 1,

    # Add quota information.  This isn't in the WebDAV
    # spec, but if it's not here, WebDrive won't allow any
    # uploads.
    '{DAV:}quota'                 => 1,
    '{DAV:}quotaused'             => 1,
    '{DAV:}quota-available-bytes' => 1,
    '{DAV:}quota-used-bytes'      => 1,
    '{DAV:}quota-assigned-bytes'  => 1,
);

# Reusable (static) XML parser
sub _XMLParser {
    $XMLParser ||= XML::LibXML->new();
    return $XMLParser;
}

# Constructor
sub new {
    my ( $class, $trace ) = @_;

    return bless(
        {
            trace => $trace || 0,
            mimeTypes => undef,
            useKVP => 0
        },
        $class
    );
}

# Modelled on CPAN:Apache::WebDAV
sub register_handlers {
    my ( $this, @handlers ) = @_;

    $this->{handlers} = \@handlers;
}

#
# Process the request. $request is the Apache request object.
# Coded to be consistent with Apache::WebDAV.
#
sub process {
    my ( $this, $request ) = @_;
    my $memHandle;

    if ( $this->{trace} & 8 ) {
        require Devel::Leak;
        $this->_trace( 8, "START MEM: " . Devel::Leak::NoteSV($memHandle) );
    }

    my $code = _process( $this, $request );

    if ( $this->{trace} & 8 ) {
        $this->_trace( 8, "END MEM: " . Devel::Leak::NoteSV($memHandle) );
    }

    return $code;
}

sub _process {
    my ( $this, $request ) = @_;

    my $uri    = $request->uri();
    my $method = uc( $request->method() );

    # Get the content now to protect it from the Foswiki startup
    # process, which will attempt to suck it dry.
    # Note from Apache docs:
    #
    # "The $r->content method will return the entity body read
    #  from the client, but only if the request content type is
    #  application/x-www-form-urlencoded."
    #
    # Can't use $r->content() because the content type is text/xml, not
    # application/x-www-form-urlencoded
    my $content = '';
    my $length = $request->headers_in->get('Content-Length');
    if ( $length ) {
        my $read = $request->read( $content, $length );
        # Die so we don't upload zero-sized content
        die "Failed to read request body" if !$read;
    }

    # Local for thread safety
    local $filesys   = $this->_getFilesys( $uri, $request );
    local $outdoc    = undef;
    local $XMLParser = undef;

    my $status = DECLINED;

    if ( $this->can($method) ) {

        # Don't auth OPTIONS or M$ Office won't be able to talk to us (it
        # doesn't send auth headers with OPTIONS)

        # meyer@modell-aachen.de:
        # I don't know why but sometimes MS Office doesn't send an authorization header
        # for an UNLOCK request. So we don't authenticate that request and relay on the lock-token.
        # SMELL: Is this safe?
        if ( $method eq 'OPTIONS' || $method eq 'UNLOCK' || $this->_processAuth($request) ) {

            # Trace Litmus special headers for debug
            $this->_trace(
                2, 'DAV:', $method, $request->uri(),
                $request->headers_in->get('X-Litmus'),
                $request->headers_in->get('X-Litmus-Second')
            );

            # KVP
            eval {
                my $session = $filesys->_initSession;
                my $web = $session->{webName};
                my $topic = $session->{topicName};
                my $talkSuffix = $Foswiki::cfg{Extensions}{KVPPlugin}{suffix} || "TALK";
                unless ( $topic =~ /^(.+)$talkSuffix$/) {
                    require Foswiki::Plugins::KVPPlugin;
                    my $kvp = Foswiki::Plugins::KVPPlugin::_initTOPIC( $web, $topic );
                    if ( defined $kvp ) {
                        my $canAttach = $kvp->canAttach;
                        my $canEdit = $kvp->canEdit;
                        my $canMove = $kvp->canMove;

                        $this->{canEdit} = $canEdit;
                        $this->{canAttach} = $canAttach;
                        $this->{canMove} = $canMove;
                        $this->{useKVP} = 1;
                    }
                }
            };
            if ( $@ ) {

            }

            $status = $this->$method( $request, $content );
            $this->_trace( 2, 'DAV:',
                '<-' . ( $status == 0 ? 'ok' : $status ) . '-',
                $method, $request->uri() );
        }
        else {
            $status = HTTP_UNAUTHORIZED;
        }
    }

    return $status;
}

sub PROPPATCH {
    my ( $this, $request, $content ) = @_;
    my $path = Encode::decode_utf8( $request->uri() );

    if ( $this->_isLockNullResource( $request, $path ) ) {
        $this->_trace( 1, 'Lock-null' );
        return HTTP_NOT_FOUND;
    }

    # Check the locks
    my @errors = $this->_checkLocks( $request, 1, undef, $path );

    if ( scalar(@errors) ) {
        return $this->_emitErrorReport( $request, @errors );
    }

    my $indoc;
    eval { $indoc = _XMLParser->parse_string($content); };
    if ($@) {
        $this->_trace( 1, $@ );
        return HTTP_BAD_REQUEST;
    }
    if ( !$indoc ) {
        $this->_trace( 1, 'No document' );
        return HTTP_BAD_REQUEST;
    }
    if ( _hasNullNamespace($indoc) ) {
        $this->_trace( 1, 'Null namespace' );
        return HTTP_BAD_REQUEST;
    }

    my $multistat = $this->_xml_new_reply('D:multistatus');
    my $response = $this->_xml_add_element( $multistat, 'D:response' );
    $this->_xml_add_href( $response, $path, 1 );

    my $pud = _firstChildNode($indoc);
    if ( _fullName($pud) ne '{DAV:}propertyupdate' ) {
        $this->_trace( 1, 'propertyupdate expected' );
        return HTTP_BAD_REQUEST;
    }

    my %statuses;
    for ( my $node = $pud->firstChild ; $node ; $node = $node->nextSibling ) {
        next unless ( $node->nodeType == 1 );
        my $method = _fullName($node);
        $method =~ s/^{DAV:}(set|remove)$/$1/;
        my $fn = $method . 'xattr';

        for ( my $prop = $node->firstChild ;
            $prop ; $prop = $prop->nextSibling )
        {
            next
              unless ( $prop->nodeType == 1
                && _fullName($prop) eq '{DAV:}prop' );
            my $pnode = _firstChildNode($prop);
            next unless $pnode;
            my $k = _fullName($pnode);
            my $v;
            if ( $pnode->firstChild ) {
                $v = $pnode->firstChild->nodeValue;
            }
            $this->_trace( 4, $method, $k, $method eq 'set' ? "$v" : '' );
            my $status = $filesys->$fn( $path, $k, $v );
            my $ns;
            my $newprop = $outdoc->createElement('D:prop');
            $this->_xml_add_propel( $newprop, $k );
            $status = $status ? HTTP_FORBIDDEN : HTTP_OK;
            push( @{ $statuses{$status} }, $newprop );
        }
    }
    $this->_xml_add_propstat( $response, %statuses );

    $this->_trace( 4, $outdoc );
    _emitBody( $outdoc->toString(0), $request );

    return OK;
}

sub COPY {
    my ( $this, $request ) = @_;
    my $path = Encode::decode_utf8( $request->uri() );

    if ( $this->_isLockNullResource( $request, $path ) ) {
        $this->_trace( 1, 'Lock-null' );
        return HTTP_NOT_FOUND;
    }

    my $destination = $request->headers_in->get('Destination');
    my $depth       = $request->headers_in->get('Depth');
    my $overwrite   = $request->headers_in->get('Overwrite') || 'T';

    $destination =
      Encode::decode_utf8(
        URI::Escape::uri_unescape( URI->new($destination)->path() ) );
    my $destHandler = $this->_getFilesys($destination);

    # Check the locks
    my @errors = $this->_checkLocks( $request, 1, $destHandler, $destination );

    if ( scalar(@errors) ) {
        return $this->_emitErrorReport( $request, @errors );
    }

    # Plain files just get copied
    if ( $filesys->test( 'f', $path ) ) {

        # If the destination already exists and it's a directory,
        # we can't proceeed
        if ( $destHandler->test( 'd', $destination ) ) {
            $this->_trace( 1, 'Destination exists and is a dir', $destination );
            return HTTP_NO_CONTENT;    # litmus/spec requires this...
        }

        if ( !$filesys->test( 'r', $path ) ) {
            $this->_trace( 1, 'Source not readable', $path );
            return HTTP_FORBIDDEN;
        }

        # HTTP_PRECONDITION_FAILED return code specified by the litmus test
        if ( $destHandler->test( 'f', $destination ) && $overwrite eq 'F' ) {
            $this->_trace( 1, 'Precondition failed', $destination );
            return HTTP_PRECONDITION_FAILED;    # Precondition Failed?
        }

        # Finally, read the source file.
        my $fh = $filesys->open_read($path);
        my $contents = join '', <$fh>;
        $filesys->close_read($fh);

        # And write the destination file
        $fh = $destHandler->open_write($destination);

        # Picked the 409 code because that's what the
        # litmus test says I should put here.
        if ( !$fh ) {
            $this->_trace( 1, 'Cannot open the destination', $destination );
            return HTTP_CONFLICT;    # huh?
        }

        print $fh $contents;
        if ( $destHandler->close_write($fh) ) {
            $this->_trace( 1, 'Cannot close the destination', $destination );
            return HTTP_FORBIDDEN;
        }

        $request->status(HTTP_CREATED);
        return OK;
    }

    # Otherwise, we're copying a collection.
    # The logic for this was taken from Net::DAV::Server.

    # 100 directory levels is as good as infinite
    $depth = 100 if defined($depth) && $depth eq 'infinity';

    # Find source files that we have to copy
    my @files =
      map { s|/+|/|g; $_ }    # simplify // to /
      File::Find::Rule::Filesys::Virtual->virtual($filesys)
      ->file->maxdepth($depth)->in($path);

    # Find source directories that we have to copy
    my @dirs = reverse sort
      grep { $_ !~ m|/\.\.?$| }    # exclude . and ..
      map { s|/+|/|g; $_ }         # simplify // to /
      File::Find::Rule::Filesys::Virtual->virtual($filesys)
      ->directory->maxdepth($depth)->in($path);

    push @dirs, $path;

    # Create directories
    foreach my $dir ( sort @dirs ) {
        my $dest_dir = $dir;

        $dest_dir =~ s/^$path/$destination/;

        if ( $overwrite eq 'F' && $destHandler->test( 'e', $dest_dir ) ) {
            $this->_trace( 1, 'Destination dir already exists', $dest_dir );
            return HTTP_UNAUTHORIZED;
        }

        if ( !$destHandler->mkdir($dest_dir) ) {
            $this->_trace( 1, 'Failed to make dir', $dest_dir );
            return HTTP_FORBIDDEN;
        }

        # If there are no files, we need to properly return from here.
        if ( !scalar(@files) ) {
            $request->status(HTTP_CREATED);
            return OK;
        }
    }

    # Copy files
    local $/;    # ignore line terminations
    foreach my $file ( reverse sort @files ) {
        my $dest_file = $file;

        $dest_file =~ s/^$path/$destination/;

        my $fh       = $filesys->open_read($file);
        my $contents = <$fh>;
        $filesys->close_read($fh);

        # Don't write if the file exists and overwrite is FALSE
        if ( $destHandler->test( 'e', $dest_file ) && $overwrite eq 'F' ) {
            $this->_trace( 1, 'File exists and !overwrite', $dest_file );
            return HTTP_UNAUTHORIZED;
        }

        # Write the new file
        $fh = $destHandler->open_write($dest_file);
        print $fh $contents;
        if ( $destHandler->close_write($fh) ) {
            $this->_trace( 1, 'Cannot close_write', $dest_file );
            return HTTP_FORBIDDEN;
        }
    }

    $request->status(HTTP_CREATED);
    return OK;
}

sub DELETE {
    my ( $this, $request ) = @_;

    if ( $this->{useKVP} ) {
        unless ( $this->{canEdit} ) {
            $this->_trace( 1, "DELETE denied by KVP." );
            return HTTP_FORBIDDEN;
        }
    }

    my $path = Encode::decode_utf8( $request->uri() );

    unless ( $filesys->test( 'e', $path ) ) {
        $this->_trace( 1, 'Cannot find', $path );
        return HTTP_NOT_FOUND;
    }

    # Get a list of all files affected by the delete request (we have to do
    # them one by one).  The ->in() method gets a list of all files under the
    # specified path recursively.
    my @files =
      grep { $_ !~ m|/\.\.?$| }    # Filter . and ..
      map { s|/+|/|g; $_ }         # Simplify // to /
      File::Find::Rule::Filesys::Virtual->virtual($filesys)->in($path), $path;

    if ( $this->_isLockNullResource( $request, @files ) ) {
        $this->_trace( 1, 'Lock-null' );
        return HTTP_NOT_FOUND;
    }

    my @errors = $this->_checkLocks( $request, 1, undef, @files );

    my %did;
    unless ( scalar(@errors) ) {
        %did = ();
        foreach my $file (@files) {
            next if $did{$file};
            $did{$file} = 1;
            next unless $filesys->test( 'e', $file );

            # make sure file exists
            if ( $filesys->test( 'f', $file ) ) {
                push( @errors, { file => $file, status => $! } )
                  unless $filesys->delete($file);
            }
            elsif ( $filesys->test( 'd', $file ) ) {
                push( @errors, { file => $file, status => $! } )
                  unless $filesys->rmdir($file);
            }
        }
    }

    if ( !scalar(@errors) ) {
        $request->status(HTTP_NO_CONTENT);
        return OK;
    }

    # SMELL: (tip from CPAN:Apache::WebDAV) WebDrive doesn't properly parse
    # HTTP_MULTI_STATUS multistatus responses for deletes.  So if it's
    # webdrive, just send a generic error code.  I know this sucks.
    #
    # Here is the response from their tech support:
    #
    # webdrive is not parsing the HTTP_MULTI_STATUS multistatus
    # response to look for the error code.  If the DELETE returns
    # an HTTP error like HTTP_FORBIDDEN instead of HTTP_MULTI_STATUS
    # then webdrive would recognize the error.  Webdrive should parse
    # the response but currently it doesn't for the DELETE command.
    # It's nothing you are doing wrong, it's just something that
    # wasn't fully implemented with webdrive and the delete command.
    return HTTP_FORBIDDEN if $this->_clientIsWebDrive($request);

    # Otherwise return a HTTP_MULTI_STATUS
    return $this->_emitErrorReport( $request, @errors );
}

sub GET {
    my ( $this, $request ) = @_;
    my $path = Encode::decode_utf8( $request->uri() );

    if ( $this->_isLockNullResource( $request, $path ) ) {
        $this->_trace( 1, 'Lock-null' );
        return HTTP_NOT_FOUND;
    }

    if ( !$filesys->test( 'r', $path ) ) {
        $this->_trace( 1, 'Cannot read', $path );
        return HTTP_FORBIDDEN;
    }

    # If the requested path is a readable file, use the Filesys::Virtual
    # interface to read the file and send it back to the client.
    if ( $filesys->test( 'f', $path ) ) {
        $request->headers_out->set(
            'Last-Modified' => '' . $filesys->modtime($path) );

        my $fh = $filesys->open_read($path);
        if ( !$fh ) {
            if ( $! == POSIX::ENOLCK ) {
                $this->_trace( 1, 'Cannot lock', $path );
                return HTTP_LOCKED;
            }
            elsif ( $! == POSIX::EACCES ) {
                $this->_trace( 1, 'Cannot access', $path );
                return HTTP_UNAUTHORIZED;
            }
            elsif ( $! == POSIX::ENOENT ) {
                $this->_trace( 1, 'No such', $path );
                return HTTP_UNPROCESSABLE_ENTITY;
            }
            elsif ( $! == POSIX::ENOTEMPTY ) {
                $this->_trace( 1, 'Not empty', $path );
                return HTTP_UNPROCESSABLE_ENTITY;
            }
            $this->_trace( 1, 'Forbidden', $path );
            return HTTP_FORBIDDEN;
        }

        local $/;
        my $file = <$fh>;

        $filesys->close_read($fh);

        my $type = $this->_deduceMimeType($path);
        $request->content_type($type) if defined $type;

        _emitBody( $file, $request );

        return OK;
    }

    # If the requested path is a directory, it's unclear what we're
    # supposed to do. Use list_details to grab some content, assumed
    # to be HTML, from the file system and chuck it out..
    if ( $filesys->test( 'd', $path ) ) {
        $request->content_type('text/html; charset="utf-8"');
	my $body = $filesys->list_details($path);
        _emitBody( $body, $request );
        return OK;
    }
    $this->_trace( 1, 'Cannot find', $path );
    return HTTP_NOT_FOUND;
}

sub HEAD {
    my ( $this, $request ) = @_;
    my $path = Encode::decode_utf8( $request->uri() );

    if ( !$filesys->test( 'e', $path ) ) {
        $this->_trace( 1, 'Does not exist', $path );
        return HTTP_NOT_FOUND;
    }

    if ( $this->_isLockNullResource( $request, $path ) ) {
        $this->_trace( 1, 'Lock-null', $path );
        return HTTP_NOT_FOUND;
    }

    if ( $filesys->test( 'd', $path ) ) {

        # Collection
        $request->content_type('text/html; charset="utf-8"');
    }
    else {

        # Plain file
        $request->headers_out->set( 'Last-Modified',
            '' . $filesys->modtime($path) );
    }

    return OK;
}

sub MKCOL {
    my ( $this, $request, $content ) = @_;
    my $path = Encode::decode_utf8( $request->uri() );
    if ( $filesys->test( 'e', $path ) ) {
        $this->_trace( 1, 'Already exists', $path );
        return HTTP_METHOD_NOT_ALLOWED;
    }
    if ($content) {
        return HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    # Check the locks
    my @errors = $this->_checkLocks( $request, 1, undef, $path );

    if ( scalar(@errors) ) {
        return $this->_emitErrorReport( $request, @errors );
    }

    $filesys->mkdir($path);

    if ( !$filesys->test( 'd', $path ) ) {
        $this->_trace( 1, 'Not a dir', $path );
        return HTTP_CONFLICT;    # What?
    }

    $request->status(HTTP_CREATED);
    return OK;
}

sub MOVE {
    my ( $this, $request ) = @_;
    my $path = Encode::decode_utf8( $request->uri() );

    if ( $this->_isLockNullResource( $request, $path ) ) {
        $this->_trace( 1, 'Lock-null', $path );
        return HTTP_NOT_FOUND;
    }

    my $destination = $request->headers_in->get('Destination');
    $destination =
      Encode::decode_utf8(
        URI::Escape::uri_unescape( URI->new($destination)->path() ) );
    my $destHandler = $this->_getFilesys($destination);

    my $overwrite = $request->headers_in->get('Overwrite') || 'T';
    my $already_exists = $destHandler->test( 'e', $destination ) || 0;

    if ($already_exists) {
        if ( $overwrite eq 'T' ) {

            # delete the target first
            # Specify the URI for the following deletion
            $request->uri( Encode::encode_utf8($destination) );
            my $result = $this->DELETE($request);

            # Reset request URI to original value
            $request->uri( Encode::encode_utf8($path) );
        }
        else {
            $this->_trace( 1, 'Target exists', $destination );
            return HTTP_PRECONDITION_FAILED;
        }
    }

    # Check the locks
    my @errors =
      $this->_checkLocks( $request, 1, $destHandler, $path, $destination );

    if ( scalar(@errors) ) {
        return $this->_emitErrorReport( $request, @errors );
    }

    if ( !( $filesys->can('rename') && ref($filesys) eq ref($destHandler) ) ) {

        # Rename not supported by the handler, or renaming to a different
        # handler. Perform a copy and then a delete, something that makes
        # sense but has specific drawbacks according to the WebDAV book.
        my $copy_result = $this->COPY($request);

        if ( $copy_result != OK ) {
            if ( $copy_result == HTTP_PRECONDITION_FAILED ) {
                return HTTP_PRECONDITION_FAILED;
            }
            elsif ( $copy_result == HTTP_NO_CONTENT ) {

                # Directory already existed
                return HTTP_FORBIDDEN;
            }
            else {
                return HTTP_FORBIDDEN;
            }
        }

        unless ( $filesys->test( 'e', $path ) ) {
            $this->_trace( 2, $path, 'does not exist' );
            return HTTP_FORBIDDEN;
        }
        if ( $filesys->test( 'd', $path ) ) {

            # Get a list of all files affected by the delete request
            # (we have to do them one by one).  The ->in() method gets
            # a list of all files under the specified path recursively.
            my @files = grep { $_ !~ m|/\.\.?$| }
              map { s|/+|/|g; $_ }    # Replace multiple slashes with single
              File::Find::Rule::Filesys::Virtual->virtual($filesys)->in($path),
              $path;

            foreach my $file (@files) {
                next unless $filesys->test( 'e', $file );

                if ( $filesys->test( 'd', $file ) ) {
                    unless ( $filesys->rmdir($file) ) {
                        $this->_trace( 2, 'rmdir', $file, 'failed:', $! );
                    }
                }
                else {
                    unless ( $filesys->delete($file) ) {
                        $this->_trace( 2, 'delete', $file, 'failed:', $! );
                    }
                }
            }
        }
        elsif ( !$filesys->delete($path) ) {
            $this->_trace( 2, 'delete', $path, 'failed:', $! );
            return HTTP_FORBIDDEN;
        }
    }
    else {

        # rename supported in the handler, and the source handler is the
        # same class as the destination handler.
        if ( !$filesys->test( 'r', $path ) ) {
            $this->_trace( 2, $path, 'is not readable' );
            return HTTP_FORBIDDEN;
        }
        if ( !$filesys->rename( $path, $destination ) ) {
            if ( $! == POSIX::ENOLCK ) {
                $this->_trace( 2, $path, 'is locked' );
                return HTTP_LOCKED;
            }
            $this->_trace( 2, $path, 'rename', $path, 'failed;', $! );
            $request->status(HTTP_UNPROCESSABLE_ENTITY);
            return HTTP_FORBIDDEN;
        }
    }
    $request->status(HTTP_CREATED);
    return OK;
}

sub OPTIONS {
    my ( $this, $request ) = @_;

    $request->headers_out->set(
        'Allow' => join( ',', grep { $this->can($_) } @METHODS ) );
    $request->headers_out->set(
        'DAV' => '1,2,<http://apache.org/dav/propset/fs/1>' );
    $request->headers_out->set( 'MS-Author-Via' => 'DAV' );
    $request->headers_out->set( 'Keep-Alive'    => 'timeout=15, max=96' );

    return OK;
}

sub PROPFIND {
    my ( $this, $request, $content ) = @_;

    my $depth = ( $request->headers_in->get('Depth') || 0 );
    my $uri = Encode::decode_utf8( $request->uri() );

    # Make sure the resource exists
    if ( !$filesys->test( 'e', $uri ) ) {
        return NOT_FOUND;
    }

    $request->status(HTTP_BAD_REQUEST);
    $request->content_type('text/xml; charset="utf-8"');

    my @files;

    if ( $depth == 0 ) {
        @files = ($uri);
    }
    elsif ( $depth == 1 ) {
        $uri =~ s/\/$//;    # strip trailing slash, we don't store it in the db

        @files = $filesys->list($uri);

        # meyer@modell-aachen.de:
        # Fix for MS Mini-Redir: remove .. but keep .
        @files = grep( $_ !~ /^\.\.$/, @files );

        # Add a trailing slash to the directory if there isn't one already
        if ( $uri !~ /\/$/ ) {
            $uri .= '/';
        }

        # Add the current folder to the front of the filename
        @files = map { $uri . $_ } @files;

        my %seen = map { $_ => 1 } @files;

        # (7.4) Add lock-null resources. These are resources that have locks,
        # but don't exist in the filesystem.
        my @locks =
          map { $_->{path} }
          grep { !$seen{ $_->{path} } && $_->{path} =~ m#^$uri/*[^/]+$# }
          $filesys->get_locks( $uri, 1 );

        $this->_trace( 4, "Lock-nulls: ", @locks );

        push( @files, @locks );
    }

    # (9.1) A client may choose not to submit a request body. An empty
    # PROPFIND request body MUST be treated as if it were an 'allprop' request.

    my $mode = 'someprop';
    my %named;
    if ($content) {

        my $indoc;
        eval { $indoc = _XMLParser->parse_string($content); };

        if ($@) {
            $this->_trace( 1, $@ );
            return HTTP_BAD_REQUEST;
        }
        if ( !$indoc ) {
            $this->_trace( 1, 'No document' );
            return HTTP_BAD_REQUEST;
        }
        if ( _hasNullNamespace($indoc) ) {
            $this->_trace( 1, 'Null namespace' );
            return HTTP_BAD_REQUEST;
        }
        my $fc = _firstChildNode($indoc);
        if ( _fullName($fc) ne '{DAV:}propfind' ) {
            $this->_trace( 1, 'Not propfind' );
            return HTTP_BAD_REQUEST;
        }

        for ( my $node = $fc->firstChild ; $node ; $node = $node->nextSibling )
        {
            next unless ( $node->nodeType == 1 );
            if ( _fullName($node) eq '{DAV:}allprop' ) {
                $mode = 'allprop';
            }
            elsif ( _fullName($node) eq '{DAV:}propname' ) {
                $mode = 'propname';
            }
            elsif ( _fullName($node) eq '{DAV:}prop' ) {
                my $prop = $node->firstChild;
                while ($prop) {
                    if ( $prop->nodeType == 1 ) {
                        my $name = _fullName($prop);

                        #print STDERR "get $name\n";
                        $named{$name} = 1;
                    }
                    $prop = $prop->nextSibling;
                }
            }
            else {
                die _fullName($node);
            }
        }
    }
    else {
        $mode = 'allprop';
    }

    # Loop through all the files and get the properties on them, and
    # compile the response.
    my $multistat = $this->_xml_new_reply('D:multistatus');

    $request->status(HTTP_MULTI_STATUS);
    foreach my $path (@files) {
        my %want;
        if ( $mode eq 'propname' ) {
            my @list;
            @list = $filesys->listxattr($path);
            pop(@list);    # status
            %want = %default_props;
            map { $want{$_} = 1 } @list;
        }
        elsif ( $mode eq 'allprop' ) {
            %want = %default_props;
        }
        else {
            %want = %named;
        }

        my $response = $this->_xml_add_element( $multistat, 'D:response' );
        $this->_xml_add_href( $response, $path, 1 );

        my %statuses;
        local $statCache;
        foreach my $propname ( keys %want ) {
            $this->_xml_find_props( $path, $propname, $mode, \%statuses );
        }
        $this->_xml_add_propstat( $response, %statuses );
    }

    $this->_trace( 4, $outdoc );
    _emitBody( $outdoc->toString(0), $request );

    return OK;
}

sub PUT {
    my ( $this, $request, $content ) = @_;

    if ( $this->{useKVP} ) {
        unless ( $this->{canAttach} ) {
            $this->_trace( 1, "PUT denied by KVP." );
            return HTTP_FORBIDDEN;
        }
    }

    my $path = Encode::decode_utf8( $request->uri() );

    # Check the locks
    my @errors = $this->_checkLocks( $request, 1, undef, $path );

    if ( scalar(@errors) ) {
        return $this->_emitErrorReport( $request, @errors );
    }

    my $fh = $filesys->open_write($path);
    if ( !$fh ) {
        if ( $! == POSIX::ENOLCK ) {
            return HTTP_LOCKED;
        }
        elsif ( $! == POSIX::EACCES ) {
            return HTTP_UNAUTHORIZED;
        }
        elsif ( $! == POSIX::ENOENT ) {
            return HTTP_UNPROCESSABLE_ENTITY;
        }
        elsif ( $! == POSIX::ENOTEMPTY ) {
            return HTTP_UNPROCESSABLE_ENTITY;
        }
        return HTTP_FORBIDDEN;
    }

    binmode $fh;
    print $fh $content;

    my $retVal = $filesys->close_write($fh);
    if ( $retVal eq 0 ) {
        $request->status(HTTP_CREATED);
        return OK;
    } elsif ( $retVal eq 1 ) {
        return HTTP_BAD_REQUEST;
    }

    return HTTP_FORBIDDEN;
}

sub LOCK {
    my ( $this, $request, $content ) = @_;

    if ( $this->{useKVP} ) {
        unless ( $this->{canEdit} ) {
            $this->_trace( 1, "LOCK denied by KVP." );
            return HTTP_FORBIDDEN;
        }
    }

    my $path = Encode::decode_utf8( $request->uri() );

    return DECLINED unless ( $filesys->can('add_lock') );

    # Get legal headers
    my $depth    = $request->headers_in->get('Depth');
    my $timeout  = $request->headers_in->get('Timeout');
    my @if       = $this->_parseIfHeader($request);
    my %lockstat = ( exclusive => 1, depth => 0, timeout => -1 );

    if ( defined $depth ) {
        if ( $depth =~ /^infinit/i ) {
            $lockstat{depth} = -1;
        }
        elsif ( $depth eq '0' ) {
            $lockstat{depth} = 0;
        }
        else {
            $this->_trace( 1, "Bad depth $depth" );
            return HTTP_BAD_REQUEST;
        }
    }
    else {
        $lockstat{depth} = -1;
    }

    if ( defined $timeout ) {
        if ( $timeout =~ /Second-(\d+)/i ) {
            $lockstat{timeout} = $1;
        }
        elsif ( $timeout =~ /^infinit/i ) {
            $lockstat{timeout} = -1;
        }
        else {

            # SMELL: could do better
            $this->_trace( 1, "Can't handle timeout $timeout" );
            return HTTP_BAD_REQUEST;
        }
    }

    my $action = 'new';

    # See if we have content (must be a lockinfo)
    if ($content) {
        my $indoc;
        eval { $indoc = _XMLParser->parse_string($content); };
        if ($@) {
            $this->_trace( 1, $@ );
            return HTTP_BAD_REQUEST;
        }
        if ( !$indoc ) {
            $this->_trace( 1, 'No document' );
            return HTTP_BAD_REQUEST;
        }

        my $fc = _firstChildNode($indoc);
        if ( _fullName($fc) ne '{DAV:}lockinfo' ) {
            $this->_trace( 1, 'lockinfo expected' );
            return HTTP_BAD_REQUEST;
        }

        for ( my $li = $fc->firstChild ; $li ; $li = $li->nextSibling ) {
            next unless $li->nodeType == 1;
            my $fn   = _fullName($li);
            my $brat = _firstChildNode($li);
            next unless ( defined $brat );
            if ( $fn eq '{DAV:}lockscope' ) {
                my $lockscope = _fullName($brat);
                if ( $lockscope eq '{DAV:}shared' ) {
                    $lockstat{exclusive} = 0;
                }
                elsif ( $lockscope ne '{DAV:}exclusive' ) {
                    $this->_trace( 1, "Bad lockscope ", $lockscope );
                    return HTTP_BAD_REQUEST;
                }
                next;
            }
            if ( $fn eq '{DAV:}locktype' ) {
                my $locktype = _fullName($brat);
                if ( $locktype ne '{DAV:}write' ) {
                    $this->_trace( 1, 'Bad locktype', $locktype );
                    return HTTP_BAD_REQUEST;
                }
                next;
            }
            if ( $fn eq '{DAV:}owner' ) {
                # $lockstat{owner} = $brat->toString();

                #TODO: possible workaround for office 2010 LOCK payload
                #$lockstat{owner} =~ s/<D:href>(.*)\\\\(.*)<\/D:href>/$1/;
                #print STDERR "BRAT--------------".$lockstat{owner}."\n";

                # meyer@modell-aachen.de:
                # According to RFC3744 - 5.1.1 - just remove the href tag.
                my $lockowner = $brat->toString();
                $lockowner =~ s/<D:href>(.*)\\(.*)<\/D:href>/$2/;
                $lockstat{owner} = $lockowner;
                next;
            }
            if ( $li->nodeType == 1 ) {
                $this->_trace( 1, 'Unrecognised lockinfo', $fn );
                return HTTP_BAD_REQUEST;
            }
        }
    }
    else {

        # Lock refresh
        $action = 'refresh';
    }

    # Check the locks. Shared locks are OK.
    my @errors =
      $this->_checkLocks( $request, $lockstat{exclusive}, undef, $path );

    if ( scalar(@errors) ) {
        return $this->_emitErrorReport( $request, @errors );
    }

    # (7.4) If the resource doesn't exist, the simple action of creating
    # the lock record will give it 'lock-null' status

    $this->_trace( 4, 'Lock is:', map { "$_=>$lockstat{$_}" } keys %lockstat );

    # Check for exclusive locks
    my @failedPaths =
      $this->_getBadLocks( 0, \@if, $filesys->get_locks( $path, 1 ) );

    if ( scalar(@failedPaths) ) {

        # Something could not be locked.
        my $multistat = $this->_xml_new_reply('D:multistatus');
        foreach my $bumPath (@failedPaths) {
            my $response = $this->_xml_add_element( $multistat, 'D:response' );
            $this->_xml_add_href( $response, $bumPath, 1 );
            $this->_xml_add_status( $response, 403 );
        }

        my $response = $this->_xml_add_element( $multistat, 'D:response' );
        $this->_xml_add_href( $response, $path, 1 );
        my $propstat = $this->_xml_add_element( $multistat, 'D:propstat' );
        my $prop     = $this->_xml_add_element( $propstat,  'D:prop' );
        my $disco    = $this->_xml_add_element( $propstat,  'D:lockdiscovery' );
        $this->_xml_fill_lockdiscovery( $disco,
            $filesys->get_locks( $path, 1 ) );
        $this->_xml_add_status( $propstat, 424 );

        $this->_trace( 4, $outdoc );
        _emitBody( $outdoc->toString(0), $request );

        return HTTP_MULTI_STATUS;
    }
    else {
        my $locktoken;
        if ( $action eq 'new' ) {
            $locktoken = 'opaquelocktoken:' . APR::UUID->new->format;
            $filesys->add_lock( path => $path, token => $locktoken, %lockstat );
            $request->headers_out->set( 'Lock-Token' => '' . $locktoken );
        }
        else {
            $locktoken = $if[0]->{token};
            $filesys->refresh_lock($locktoken);
        }
        $lockstat{token} = $locktoken;

        # Resource was successfully locked. If the resource does not exist,
        # it will be seen as a lock-null resource.
        my $prop = $this->_xml_new_reply('D:prop');
        my $disco = $this->_xml_add_element( $prop, 'D:lockdiscovery' );
        $this->_xml_fill_lockdiscovery( $disco, \%lockstat );

        $request->status(HTTP_OK);
        $request->content_type('text/xml; charset="utf-8"');

        $this->_trace( 4, $outdoc );
        _emitBody( $outdoc->toString(0), $request );
    }

    return OK;
}

sub UNLOCK {
    my ( $this, $request ) = @_;

    my $path = Encode::decode_utf8( $request->uri() );
    my $locktoken = $request->headers_in->get('Lock-Token');

    # meyer@modell-aachen.de
    # see below
    unless ( $locktoken ) {
        $this->_trace( 1, 'No locktoken given', $path );
        return HTTP_FORBIDDEN;
    }

    $locktoken =~ s/<(.*)>/$1/;

    # meyer@modell-aachen.de
    # Fix:
    # Returning a 403 although there is no lock for the given token
    # will prevent MS Office from sending a proper lockinfo request.
    # (Office keeps its token until the according lock is released)
    my $hasLock = $filesys->has_lock( $locktoken );
    if ( $filesys->remove_lock($locktoken) || !$hasLock ) {
        $request->status( HTTP_NO_CONTENT );
        return OK;
    }
    $this->_trace( 1, 'Could not unlock', $path );
    return HTTP_FORBIDDEN;
}

#
# Private methods below here.
#

# Emit tracing information to the Apache error log
sub _trace {
    my $this  = shift;
    my $level = shift;
    if ( $this->{trace} & $level ) {
        if ( ref( $_[0] ) ) {
            print STDERR $_[0]->toString() . "\n";
        }
        else {
            print STDERR join( ' ', @_ ) . "\n";
        }
    }
}

# Find the first non-text child node of an XML node
sub _firstChildNode {
    my $node  = shift;
    my $child = $node->firstChild;
    while ( $child && $child->nodeType != 1 ) {
        $child = $child->nextSibling;
    }
    return $child;
}

# Given an XML node, flatten the namespace out so we get (for example)
# <a:node xmlns="a:http://blah">
# as
# {http://blah:}node
# Read the doc for XML::Simple if that isn't clear
sub _fullName {
    my $node = shift;
    return '' unless $node;
    return $node->nodeName unless $node->nodeType eq 1;    # elements
    my $ns = $node->namespaceURI();
    if ( defined $ns ) {
        return "{$ns}" . $node->localname;
    }

    # Check for the null namespace, in case it was defined
    my @nses = $node->getNamespaces();
    foreach my $n (@nses) {
        if ( ref($n) eq 'XML::LibXML::Namespace' ) {
            return '{' . $n->getData() . '}' . $node->localname;
        }
    }

    # (8.1.3) all elements which do not explicitly state the
    # namespace to which they belong are members of the "DAV:"
    # namespace schema.
    return "{DAV:}" . $node->localname;
}

# Test for different user agents
sub _clientIsWebDrive {
    my ( $this, $request ) = @_;
    return $request->headers_in->get('User-Agent') =~ /WebDrive/;
}

sub _clientIsLitmus {
    my ( $this, $request ) = @_;
    return $request->headers_in->get('User-Agent') =~ /litmus/;
}

sub _clientIsMSOffice {
    my ( $this, $request ) = @_;
    # Office < 2013
    my $isCoreStorage = $request->headers_in->get('User-Agent') =~ /Microsoft Office Core Storage Infrastructure/;

    # Office 2013
    # UAs: Microsoft Office Upload Center 2013 (15.0.4420) Windows NT 6.1
    #      Microsoft Office Word 2013 (15.0.4420) Windows NT 6.1
    #      ...
    my $isOffice2013 = $request->headers_in->get('User-Agent') =~ /Microsoft Office(.+)2013/;

    return ($isCoreStorage || $isOffice2013);
}

# (7.4) See if any of these resources are lock null (they don't exist in the
# filesystem, but have active locks)
sub _isLockNullResource {
    my ( $this, $request, @files ) = @_;
    my $handler = $filesys;
    foreach my $file (@files) {
        my @locks = $handler->get_locks($file);
        foreach my $lock (@locks) {

            # If the resource doesn't exist, this is a lock-null
            unless ( $handler->test( 'e', $file ) ) {
                $this->_trace( 1, 'Lock-null because of', $file );
                return 1;
            }
        }
    }
    return 0;
}

# Check the locks on the resources, returning any that are locked
# but we don't have a lock token for as an error message suitable
# for use with _emitErrorReport
sub _checkLocks {
    my ( $this, $request, $checkShared, $handler, @files ) = @_;
    $handler ||= $filesys;
    my %did;
    my @if     = $this->_parseIfHeader($request);
    my @errors = ();
    foreach my $file (@files) {
        next if $did{$file};
        $did{$file} = 1;
        my @fails =
          $this->_getBadLocks( $checkShared, \@if, $handler->get_locks($file) );
        foreach my $fail (@fails) {
            push( @errors, { file => $fail, status => HTTP_LOCKED } );
        }
    }
    return @errors;
}

# Check if any of the listed locks meet the criteria expressed in an
# If: header
sub _getBadLocks {
    my ( $this, $checkShared, $if, @locks ) = @_;
    my @failedPaths;
  LOCK:
    foreach my $lock (@locks) {
        if ( $checkShared || $lock->{exclusive} ) {
            foreach my $i (@$if) {
                next unless defined $i->{token};
                next LOCK
                  if ( $i->{token} eq $lock->{token} && !$i->{invert} )
                  || ( $i->{token} ne $lock->{token} && $i->{invert} );
            }

            # SMELL: Must check the owner
            push( @failedPaths, $lock->{path} );
            $this->_trace( 4, 'LOCKED', Data::Dumper->Dump( [$lock] ) );
        }
    }
    return @failedPaths;
}

# Emit a multistatus report of the errors in @errors, each of the format
# { file => ..., status => ... }
sub _emitErrorReport {
    my ( $this, $request, @errors ) = @_;

    # SMELL: litmus doesn't understand a multistatus response to
    # the delete request, despite it being exactly as shown in the spec
    return HTTP_LOCKED
      if $this->_clientIsLitmus($request) || $request->header_only();

    # meyer@modell-aachen.de:
    # MS Office doesn't parse the multistatus response.
    # Returning HTTP_LOCKED forces Office to show a "file locked" dialog to the user.
    return HTTP_LOCKED
      if $this->_clientIsMSOffice( $request );

    # Many errors, return multistatus
    my $multistat = $this->_xml_new_reply('D:multistatus');
    foreach my $error (@errors) {
        my $response = $this->_xml_add_element( $multistat, 'D:response' );
        $this->_xml_add_href( $response, $error->{file}, 1 );
        $this->_xml_add_status( $response, $error->{status} );
    }

    $request->content_type('text/xml; charset="utf-8"');

    $this->_trace( 4, $outdoc );
    _emitBody( $outdoc->toString(0), $request );

    $request->status(HTTP_MULTI_STATUS);
    return HTTP_MULTI_STATUS;
}

sub _xml_add_element {
    my ( $this, $parent, $el ) = @_;
    my $node = $outdoc->createElement($el);
    $parent->addChild($node);
    return $node;
}

sub _xml_new_reply {
    my ( $this, $rootel ) = @_;
    $outdoc = new XML::LibXML::Document( '1.0', 'utf-8' );
    my $root = $outdoc->createElement($rootel);
    $root->setAttribute( 'xmlns:D', 'DAV:' );
    $outdoc->setDocumentElement($root);
    return $root;
}

sub _xml_add_href {
    my ( $this, $response, $path, $encode ) = @_;
    if ($encode) {
        $path = join( '/',
            map { URI::Escape::uri_escape( Encode::encode_utf8($_) ) }
              split( /\/+/, $path ) );
    }
    $response->appendTextChild( 'D:href' => $path );
}

# Generate the lockdiscovery content for the locks in @locks
sub _xml_fill_lockdiscovery {
    my ( $this, $disco, @locks ) = @_;

    foreach my $lock (@locks) {
        my $alock = $this->_xml_add_element( $disco, 'D:activelock' );

        my $e = $this->_xml_add_element( $alock, 'D:lockscope' );
        $this->_xml_add_element( $e,
            'D:' . ( $lock->{exclusive} ? 'exclusive' : 'shared' ) );

        $alock->appendTextChild(
            'D:depth' => $lock->{depth} < 0 ? 'Infinity' : $lock->{depth} );

        $e = $this->_xml_add_element( $alock, 'D:locktype' );
        $this->_xml_add_element( $e, 'D:write' );

        if ( $lock->{owner} ) {
            $e = $this->_xml_add_element( $alock, 'D:owner' );
            $this->_xml_add_href( $e, $lock->{owner}, 0 );
        }

        $e = $this->_xml_add_element( $alock, 'D:locktoken' );
        $this->_xml_add_href( $e, $lock->{token}, 0 );

        $alock->appendTextChild(
              'D:timeout' => $lock->{timeout} < 0
            ? 'Infinite'
            : "Second-$lock->{timeout}"
        );
    }
}

# From the litmus FAQ:
# "If a request was sent with an XML body which included an empty
#  namespace prefix declaration (xmlns:ns1=""), then the server
#  must reject that with a "400 Bad Request" response, as it is
#  invalid according to the XML Namespace specification."
# This is tested by litmus using:
# <D:propfind xmlns:D="DAV:"><D:prop><bar:foo xmlns:bar=""/>
# </D:prop></D:propfind>
# So the definition of an "null namespace" is one with a
# declared prefix but no declared URI. Check it.
sub _hasNullNamespace {
    my $node = shift;
    my @nses = $node->getNamespaces();
    foreach my $n (@nses) {
        if ( ref($n) eq 'XML::LibXML::Namespace' ) {
            return 1 if $n->declaredPrefix() && !$n->declaredURI();
        }
    }
    for ( my $sn = $node->firstChild ; $sn ; $sn = $sn->nextSibling ) {
        next unless $sn->nodeType == 1;
        return 1 if _hasNullNamespace($sn);
    }
    return 0;
}

# Parse an If: header and return a simple hash representation
# If = "If" ":" ( 1*No-tag-list | 1*Tagged-list)
# No-tag-list = List
# Tagged-list = Resource 1*List
# Resource = Coded-URL
# List = "(" 1*(["Not"](State-token | "[" entity-tag "]")) ")"
# State-token = Coded-URL
# Coded-URL = "<" absoluteURI ">"
#
# Returns a list of constraints
sub _parseIfHeader {
    my ( $this, $request ) = @_;
    my $if = $request->headers_in->get('If');
    return () unless defined $if;

    # meyer@modell-aachen.de:
    # Fix for MS Office 2010 and greater
    if ( $if =~ /opaquelocktoken/ ) {
        if ( $if !~ m/^\s*\(<(.*?)>\)\s*$/ ) {
            $if =~ s/^\s*\((.*?)\)\s*$/\(<$1>\)/;
        }
    }

    my @headers = ();

    while ( $if =~ /\S/ ) {
        my $match = {};
        if ( $if =~ s/^\s*<(.*?)>// ) {

            # coded URL
            $match->{resource} = $1;
        }
        if ( $if =~ s/^\s*\(// ) {
            if ( $if =~ s/^\s*Not// ) {
                $match->{invert} = 1;
            }
            if ( $if =~ s/^\s*\[\s*\"(.*?)\"\s*\]// ) {
                $match->{etag} = $1;
            }
            elsif ( $if =~ s/^\s*<(.*?)>// ) {
                $match->{token} = $1;
            }
            $if =~ s/^\s*\)//;
        }
        push( @headers, $match );
    }
    return @headers;
}

sub _xml_add_status {
    my ( $this, $propstat, $code ) = @_;
    my $stat = $this->_xml_add_element( $propstat, 'D:status' );
    $stat->appendText(
        'HTTP/1.1 ' . Apache2::RequestUtil::get_status_line($code) );
}

# Add <D:propstat> to a response
sub _xml_add_propstat {
    my ( $this, $response, %statuses ) = @_;

    my $doc = $response->ownerDocument;
    foreach my $status ( keys %statuses ) {
        my $propstat = $doc->createElement('D:propstat');
        my $prop     = $doc->createElement('D:prop');
        foreach my $pel ( @{ $statuses{$status} } ) {
            next unless $pel->firstChild;
            $prop->addChild( $pel->firstChild );
        }
        $propstat->addChild($prop);
        $this->_xml_add_status( $propstat, $status );
        $response->addChild($propstat);
    }
}

# Get XML for property values, storing the resulting elements in
# a hash keyed on the response status.
sub _xml_find_props {
    my ( $this, $path, $propname, $mode, $statuses ) = @_;
    my $info   = {};
    my $status = HTTP_OK;
    my $propel = $outdoc->createElement('D:prop');

    # get the property value
    my $datum = $this->_xml_add_propel( $propel, $propname );
    if ( $mode ne 'propname' ) {
        if ( $default_props{$propname} ) {
            $this->_xml_fill_live_prop( $datum, $path, $propname );
        }
        else {
            my $val = $filesys->getxattr( $path, $propname );
            if ( defined $val ) {
                $datum->appendText($val);
            }
            else {
                $status = HTTP_NOT_FOUND;
            }
        }
    }

    push( @{ $statuses->{$status} }, $propel );
}

# Add an XML element for a property
sub _xml_add_propel {
    my ( $this, $parent, $name ) = @_;
    my $datum;
    if ( $name =~ /{(.*)}(.*?)$/ ) {
        if ( $1 eq 'DAV:' ) {
            $datum = $this->_xml_add_element( $parent, "D:$2" );
        }
        else {
            $datum = $outdoc->createElementNS( $1, $2 );
            $parent->addChild($datum);
        }
    }
    else {
        $datum = $this->_xml_add_element( $parent, $name );
    }
    return $datum;
}

# Get a live property value for a resource. Modelled on Apache:WebDAV
# SMELL: this could be done a lot better.
sub _xml_fill_live_prop {
    my ( $this, $datum, $path, $name ) = @_;

    unless ($statCache) {

        # The list of properties in the order a stat()
        # call returns.
        my @properties = qw(dev ino mode nlink uid gid rdev
          getcontentlength atime getlastmodified
          creationdate);
        $statCache = {};
        my @stat = $filesys->stat($path);
        my $i    = 0;
        foreach my $p (@properties) {
            $statCache->{$p} = $stat[ $i++ ];
        }
    }

    if ( $name eq '{DAV:}getetag' ) {

        # Format consistent with mod_dav_fs
        my $etag;
        if ( $statCache->{ino} ) {
            $etag = sprintf( '"%x-%x-%x"',
                $statCache->{ino},
                $statCache->{getcontentlength} || 0,
                $statCache->{getlastmodified}  || 0 );
        }
        else {
            $etag = sprintf( '"%x"', $statCache->{getlastmodified} || 0 );
        }

        $datum->appendText($etag);
    }
    elsif ( $name eq '{DAV:}creationdate' ) {
        $datum->appendText( _formatISOTime( $statCache->{creationdate} || 0 ) );
    }
    elsif ( $name eq '{DAV:}getlastmodified' ) {
        $datum->appendText(
            _formatHTTPTime( $statCache->{getlastmodified} || 0 ) );
    }
    elsif ( $name eq '{DAV:}getcontentlength' ) {
        $datum->appendText( $statCache->{getcontentlength} || 0 );
    }
    elsif ($name eq '{DAV:}supportedlock'
        && $filesys->can('add_lock') )
    {
        my $info = $filesys->lock_types($path);

        my @types = ( exclusive => 1, shared => 2 );
        while ( scalar(@types) ) {
            my $k = shift(@types);
            my $n = shift(@types);
            if ( $info & $n ) {
                my $lockentry =
                  $this->_xml_add_element( $datum, 'D:lockentry' );
                my $lockscope =
                  $this->_xml_add_element( $lockentry, 'D:lockscope' );
                $this->_xml_add_element( $lockscope, 'D:' . $k );

                # Write locks are the only supported lock type
                my $type = $this->_xml_add_element( $lockentry, 'D:locktype' );
                $this->_xml_add_element( $type, 'D:write' );
            }
        }
    }
    elsif ( $name eq '{DAV:}resourcetype' ) {
        if ( $filesys->test( 'd', $path ) ) {
            $this->_xml_add_element( $datum, 'D:collection' );
        }
    }
    elsif ( $name eq '{DAV:}getcontenttype' ) {
        if ( $filesys->test( 'd', $path ) ) {
            $datum->appendText('httpd/unix-directory');
        }
        else {
            my $type =
              $this->_deduceMimeType($path) || 'application/octet-stream';
            $datum->appendText($type);
        }
    }
    elsif ( $name eq '{DAV:}lockdiscovery' ) {
        $this->_xml_fill_lockdiscovery( $datum,
            $filesys->get_locks( $path, 1 ) );
    }
    elsif ( $name eq '{DAV:}getcontentlanguage' ) {
        $datum->appendText('');
    }
    elsif ( $name =~ /^{DAV:}quota(used|-used-bytes)$/ ) {
        $datum->appendText('0');
    }
    elsif ( $name =~ /^{DAV:}quota(-available-bytes|-assigned-bytes)$/ ) {
        $datum->appendText('2000000000');
    }
}


# Based on the requested path, figure out which Filesys::Virtual module
# will handle the request.
sub _getFilesys {
    my ( $this, $uri, $request ) = @_;

    # Based on the requested path ($uri), figure out which module will
    # handle the request.  The modules must be subclasses of
    # Filesys::Virtual.
    my $module;
    my $path_handled;
    my %args;

    foreach my $mod ( @{ $this->{handlers} } ) {
        my $path = $mod->{path};
        if ( $uri =~ /^$path/ ) {
            $module       = $mod->{module};
            $path_handled = $path;
            %args         = %{ $mod->{args} } if defined( $mod->{args} );
            last;
        }
    }

    die "Could not find handler for $uri" unless $module;

    eval "use $module";

    die "Failed to load $module: $@" if $@;
    my $handler = $module->new(
        {
            root_path => $path_handled,
            cwd       => $uri,
            %args
        }
    );
    return $handler;
}

# If the handler requires a login, pass the auth from the request on to it.
# Only supports Basic auth ATM
sub _processAuth {
    my ( $this, $request ) = @_;

    if ( $request->some_auth_required() ) {

        # The current request is authenticated
        if ( $filesys->can('login') ) {

            # filesystem supports login

            # using the apache user
            my $loginName = $request->user();
            unless ( $loginName ) {
                # _emitBody( "ERROR: (401) Invalid login.", $request );
                $request->status(HTTP_UNAUTHORIZED);
                return 0;
            }

            # Windows insists on sticking the domain in front of the the
            # username. Chop it off if the mini-redirector is requesting.
            my $userAgent = $request->headers_in->get('User-Agent') || '';

            # meyer@modell-aachen.de
            if ( !$Foswiki::cfg{WebDAVContrib}{KeepWindowsDomain} ) {
              if ( $loginName && ($loginName =~ m/^(.+)\@.*$/ || $loginName =~ m/^.*\\(.+)$/) ) {
                $loginName = $1;
              }
            }

            # meyer@modell-aachen.de
            # normalize loginName by using LdapContrib and rewrite to lowercase.
            if ( $Foswiki::cfg{Ldap}{NormalizeLoginNames} ) {
              require Foswiki::Contrib::LdapContrib;
              $loginName = Foswiki::Contrib::LdapContrib::transliterate( $loginName );
              $loginName = "\L$loginName";
            }

            unless ( $filesys->login($loginName) ) {
                $this->_trace( 1, 'Login failed for ' . $loginName );
                # Login failed; reject the request
                $request->content_type('text/html; charset="utf-8"');
                _emitBody( "ERROR: (401) Can't login as $loginName", $request );
                return 0;
            }
            $this->_trace( 2, $loginName . ' logged in' );
        }
        else {
            print STDERR 'WebDAV: file system does not support auth';
            _emitBody( "ERROR: (401) Can't login to filesystem", $request );
            return 0;
        }
    }
    return 1;
}

# Emit the string as the body of a response
sub _emitBody {
    my ( $string, $request ) = @_;

    $string ||= '';

    # Have to use content-length because Windows Mini-Redirector doesn't
    # understand chunked encoding.
    $request->headers_out->set( 'Content-Length', length($string) );
    $request->print($string);
}

# Format ISO8601 date
sub _formatISOTime {
    my $t = shift;
    return "1970-01-01" unless defined $t;
    my ( $sec, $min, $hour, $day, $mon, $year, $wday, $tz_str ) = gmtime($t);
    return
        sprintf( '%.4u', $year + 1900 ) . "-"
      . sprintf( '%.2u', $mon + 1 ) . "-"
      . sprintf( '%.2u', $day ) . "T"
      . sprintf( '%.2u', $hour ) . ":"
      . sprintf( '%.2u', $min ) . ':'
      . sprintf( '%.2u', $sec ) . "Z";
}

sub _formatHTTPTime {
    my $t = shift;
    my ( $sec, $min, $hour, $day, $mon, $year, $wday, $tz_str ) = gmtime($t);
    return
        $WEEKDAY[$wday]
      . ", $day $ISOMONTH[$mon] "
      . sprintf( '%.4u', $year + 1900 ) . " "
      . sprintf( '%.2u', $hour ) . ":"
      . sprintf( '%.2u', $min ) . ':'
      . sprintf( '%.2u', $sec ) . " GMT";
}

# Look up mime types DB to map a file extension to a mime type
sub _deduceMimeType {
    my ( $this, $path ) = @_;

    return undef unless ( $path =~ /\.([^.]*)$/ );
    my $ext = $1;
    unless ( $this->{mimeTypes} ) {
        my $tree        = Apache2::Directive::conftree();
        my $typesConfig = $tree->lookup('TypesConfig');
        my $f;
        open( $f, '<', $typesConfig ) || return $!;
        local $/ = "\n";
        my %mimeTypes;
        while ( my $line = <$f> ) {
            next if $line =~ /^\s*#/;
            if ( $line =~ /(\S+)\s*(.*?)\s*$/ ) {
                my $type = $1;
                foreach my $extension ( split( /\s+/, $2 ) ) {
                    $mimeTypes{$extension} = $type;
                }
            }
        }
        close($f);
        $this->{mimeTypes} = \%mimeTypes;
    }
    return $this->{mimeTypes}->{$ext};
}

1;
__END__

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
