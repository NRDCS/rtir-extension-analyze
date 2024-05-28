use strict;
use warnings;
package RTIR::Extension::Analyze;

our $VERSION = '0.01';

=head1 NAME

RTIR-Extension-Analyze - Menu and action to send CF values to analysis services

=head1 DESCRIPTION

Extension adds menu item Analyze on the Incident ticket menu. From there you can send 
HTTP requests to external services (webhooks) sending together ticket ID as a context.
External service supposed to retrieve CF values from the ticket and submit to analysis
procedure.

=head1 RT VERSION

Works with RT [What versions of RT is this known to work with?]

[Make sure to use requires_rt and rt_too_new in Makefile.PL]

=head1 INSTALLATION

=over

=item C<perl Makefile.PL>

=item C<make>

=item C<make install>

May need root permissions

=item Edit your F</opt/rt4/etc/RT_SiteConfig.pm>

Add this line:

    Plugin('RTIR::Extension::Analyze');

=item Clear your mason cache

    rm -rf /opt/rt5/var/mason_data/obj

=item Restart your webserver

=back

=head1 AUTHOR

Best Practical Solutions, LLC E<lt>modules@bestpractical.comE<gt>

=for html <p>All bugs should be reported via email to <a
href="mailto:bug-RTIR-Extension-Analyze@rt.cpan.org">bug-RTIR-Extension-Analyze@rt.cpan.org</a>
or via the web at <a
href="http://rt.cpan.org/Public/Dist/Display.html?Name=RTIR-Extension-Analyze">rt.cpan.org</a>.</p>

=for text
    All bugs should be reported via email to
        bug-RTIR-Extension-Analyze@rt.cpan.org
    or via the web at
        http://rt.cpan.org/Public/Dist/Display.html?Name=RTIR-Extension-Analyze

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2024 by Marius Urkis

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991

=cut

use JSON;
use LWP::UserAgent;
use IO::Socket::SSL;

sub AnalysisRequest {
    my $self = shift;
    my $Ticket = shift;
    my $AnalysisServiceName = shift;
    RT::Logger->debug("Analysis requested for ticket ".$Ticket->id.", service: ".$AnalysisServiceName);
    return (0, "Rights not sufficient for the analysis action") unless $Ticket->CurrentUserHasRight('ModifyTicket');
    my %AnalysisServices = RT->Config->Get('CSET_AnalysisServices');
    
    use Data::Dumper;

    return (0, "Analysis services not configured") unless (exists $AnalysisServices{$AnalysisServiceName});

    my $api_url = $AnalysisServices{$AnalysisServiceName}->{'URL'};
    my $headers = $AnalysisServices{$AnalysisServiceName}->{'Headers'};
    my $skip_ssl = $AnalysisServices{$AnalysisServiceName}->{'SkipSSLVerification'} || 0;
    my $timeout = $AnalysisServices{$AnalysisServiceName}->{'Timeout'} || 3;

    my %data = ( 
        ticket => $Ticket->id
    );



    my $client = build_http_client($skip_ssl, $timeout);
    foreach my $header (@{$headers}) {

        $client->default_header($header->{'Header'} => $header->{'Value'});

    }
    my $response = $client->post(
        $api_url,
        Content      => encode_json(\%data),
        Content_Type => 'application/json'
    );
    unless ($response->is_success) {
        RT->Logger->error(sprintf("[Analysis]: %s", $response->content));
        return (0, $response->content);
    }

    return (1, $response->content);
}


sub build_http_client {
    my $skip_ssl = shift;
    my $timeout = shift;
    my  $client = LWP::UserAgent->new(timeout => $timeout);
    $client->ssl_opts(
            SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE,
            verify_hostname => 0) if $skip_ssl;
    return $client;

}


1;
