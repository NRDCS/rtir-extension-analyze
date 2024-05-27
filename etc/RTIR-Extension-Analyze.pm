Set(%CSET_AnalysisServices,(
  'IP Reputation Analysis' => {
    URL =>'https://10.20.30.40/api/v1/hooks/webhook_abcdef_123456789_abcdef',
    Headers => [
      {Header => 'Authorization', Value => 'Token xyzxyz12345612346'}
    ],
    SkipSSLVerification => 1
  }
));

1;