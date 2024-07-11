use lib '.';
use inc::Module::Install;

RTx     'RTIR-Extension-Analyze';
license 'gpl_2';
repository 'https://github.com/bestpractical/rtir-extension-analyze';

requires_rt '5.0.0';
rt_too_new '5.2.0';

sign;
WriteAll;
