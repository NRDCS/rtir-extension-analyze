use strict;
use warnings;
package RTIR::Extension::Analyze;

our $VERSION = '0.01';

=head1 NAME

RTIR-Extension-Analyze - Menu and action to send a request to analysis services

=head1 DESCRIPTION

Extension adds menu item Analyze on the Incident or other queue ticket menu. 
From there you can send HTTP requests to external services (webhooks) sending 
together ticket ID as a context. External service (orchestrator) supposed to 
retrieve CF values from the ticket and submit to analysis procedure. After 
analysis is finished, orchestrator can update ticket with results, do 
notification or any other action.

=head1 RT VERSION

Works with RT 5.0.5

=head1 INSTALLATION

=over

=item C<perl Makefile.PL>

=item C<make>

=item C<make install>

May need root permissions

=item Edit your F</opt/rt5/etc/RT_SiteConfig.pm>

Add this line:

    Plugin('RTIR::Extension::Analyze');

Add configuration, use file etc/RTIR-Extension-Analyze.pm as a template.

=item Clear your mason cache

    rm -rf /opt/rt5/var/mason_data/obj

=item Restart your webserver

=back

=head1 AUTHOR

Marius Urkis, NRD CyberSecurity E<lt>cyberset@nrdcs.ltE<gt>

=for html <p>All bugs should be reported via email to <a
href="mailto:cybercet@nrdcs.lt">cybercet@nrdcs.lt</a>


=for text
    All bugs should be reported via email to
        cybercet@nrdcs.lt

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
    # Skipping if not owner or other privileges not enough
    return (0, "Rights not sufficient for the analysis action") unless $Ticket->CurrentUserHasRight('ModifyTicket');
    # Retrieving configuration
    my $queueName = $Ticket->QueueObj->Name();
    return (0, "Analysis services not configured") unless RT->Config->Get('CSET_AnalysisServices')->{$queueName};

    my $AnalysisServices = RT->Config->Get('CSET_AnalysisServices')->{$queueName};
    return (0, "Analysis services not configured") unless (exists $AnalysisServices->{$AnalysisServiceName});
    my $api_url = $AnalysisServices->{$AnalysisServiceName}->{'URL'};
    my $headers = $AnalysisServices->{$AnalysisServiceName}->{'Headers'};
    my $skip_ssl = $AnalysisServices->{$AnalysisServiceName}->{'SkipSSLVerification'} || 0;
    my $timeout = $AnalysisServices->{$AnalysisServiceName}->{'Timeout'} || 3;
    # Sending simple data to analysis service. containing only ticket id
    # Assuming analysis service will retrieve data from ticket needed for analysis
    my %data = ( 
        ticket => $Ticket->id
    );

    my $client = build_http_client($skip_ssl, $timeout);

    # setting up headers, e.g authorization
    foreach my $header (@{$headers}) {
        $client->default_header($header->{'Header'} => $header->{'Value'});
    }
    # POSTing data
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
