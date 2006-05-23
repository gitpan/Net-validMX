#!/usr/bin/perl

use strict;
use Net::validMX;

my ($rv, $reason, $failtotal, $passtotal, $default_tests, $email);

print "Net::ValidMX v".&Net::validMX::version()."\n\n";

$default_tests = 1;

#RUN ME WITH EMAIL ADDRESS PARAMETERS OR I'LL RUN DEFAULT TESTS
if (scalar(@ARGV) > 0) {
  while (@ARGV) {
    $ARGV = shift @ARGV;    

    if ($ARGV =~ /\@/) {
      $default_tests--;
      ($rv, $reason) = &Net::validMX::check_valid_mx($ARGV);
      $failtotal += ($rv < 1);
      $passtotal += $rv;

      print &Net::validMX::get_output_result($ARGV, $rv, $reason);
    } else {
      print "Invalid Argument: $ARGV\n";
    }
  }
} 

if ($default_tests > 0) {
  # TESTS I THINK SHOULD PASS
  $failtotal = 0;
  $passtotal = 0;
  
  print "\nTests Expected to Pass:\n";
  
  #Tests correct DNS - Should Pass
  $email = 'kevin.mcgrail@thoughtworthy.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;

  #Tests non-rfc compliant DNS using cname for MX - Should Pass
  $email = 'test@tri-llama.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;

  #Tests for implicit MX by A record - Should Pass
  $email = 'test@mail.mcgrail.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  
  #Tests for something that was throwing an error in v1 where we need to discard the first answer on a CNAME domain - Should Pass
  $email = 'AirchieChalmers@londo.cysticercus.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;

  $email = 'OlgaCraft@barbequesauceofthemonthclub.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  
  #Tests for use of crazy things like 12.34.56.78. as the host name in DNS - Should Pass if $allow_ip_address_as_mx = 1;
  $email = 'test@test.peregrinehw.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  #Tests for use of crazy things like 192.168.0.1. as the host name in DNS - Should Pass if $allow_ip_address_as_mx = 1;
  $email = 'test@test2.peregrinehw.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  #Test for odd top level domain setups like .va for the vatican
  $email = 'god@va';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  
  #Tests for a host that is configured with an MX of . but eventually has a good MX recorded (due to eNom.com (name-services.com) false positives - Should Pass
  $email = 'test@test6.peregrinehw.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  
  print "\n# of Failures for Tests Expected to Pass: $failtotal\n";
  print "# of Successes for Tests Expected to Pass: $passtotal\n";
  
  
  # TESTS I'M UNSURE SHOULD FAIL OR NOT
  
  $failtotal = 0;
  $passtotal = 0;
  
  print "\nTests I'm unsure if they should or should not Fail:\n";
  
  #RESOLVES TO AN IMPLICIT CNAME THAT IS CHAINED TO A CNAME
  $email = 'zacaris@muska.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  
  print "\n# of Failures for Uncertain Tests: $failtotal\n";
  print "# of Successes for Uncertain Tests: $passtotal\n";
  
  
  
  # TESTS THAT SHOULD FAIL
  
  $failtotal = 0;
  $passtotal = 0;
  
  print "\nTests Expected to Fail:\n";
  
  #Tests for a host that is configured with an MX of . & priority 10 which will be considered a pass due eNom.com (name-services.com) false positives - Should Fail if it's the only MX
  $email = 'test@test4.peregrinehw.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  
  #Test for non-FQDN
  $email = 'nofrom@www';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;

  #Test for Explicit IP instead of domain name
  $email = 'postmaster@[127.0.0.1]';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  
  #Tests for a host that is configured with an MX of . & priority 0 which is a 'I don't do email' Notification - Should Fail
  $email = 'test@test3.peregrinehw.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  
  #tests for incorrect DNS
  $email = 'zqy152214@liyuanculture.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;

  $email = 'formation2005@carmail.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;

  #NO LONGER FAILS AS OF 5-23-06
  #$email = 'chaifai@flashmail.net';
  #($rv, $reason) = &Net::validMX::check_valid_mx($email);
  #print &Net::validMX::get_output_result($email, $rv, $reason);
  #$failtotal += ($rv < 1);
  #$passtotal += $rv;
  
  #Test for privatized IP range use only
  $email = 'test@geg.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;

  $email = 'test@test5.peregrinehw.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;
  
  #Tests for non-resolvable MX records
  $email = 'test@tennesseen.com';
  ($rv, $reason) = &Net::validMX::check_valid_mx($email);
  print &Net::validMX::get_output_result($email, $rv, $reason);
  $failtotal += ($rv < 1);
  $passtotal += $rv;

  #AS OF 5-23-06 IS PUBLISHING BLOCKEDMAIL.COM AS MX AT PRIORITY 0
  #$email = 'test@8888.com';
  #($rv, $reason) = &Net::validMX::check_valid_mx($email);
  #print &Net::validMX::get_output_result($email, $rv, $reason);
  #$failtotal += ($rv < 1);
  #$passtotal += $rv;
  
  print "\n# of Failures for Tests Expected to Fail: $failtotal\n";
  print "# of Successes for Tests Expected to Fail: $passtotal\n";
}

exit;
