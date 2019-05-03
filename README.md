# pmd-apex-kiuwan-plugin
An utility to import [PMD (Apex language)](https://pmd.github.io/latest/pmd_rules_apex.html) reports to kiuwan.

## install and run
If you are an impatient person, here are the steps to install and run this plugin in your kiuwan analysis:
1. copy dist/pmd-apex-kiuwan-plugin-x.y.z.jar in your {KIUWAN\_LOCAL\_ANALYZER\_INSTALLATION\_DIR}/lib.custom directory.

1. install pmd-apex-kiuwan-plugin/src/main/resources/ruledef files in your kiuwan account. See more on this at [Installing rule definitions](https://www.kiuwan.com/docs/display/K5/Installing+rule+definitions+created+with+Kiuwan+Rule+Developer)

1. creates a new model with this new rules, and assign the model to your kiuwan APEX applications

1. edit your {KIUWAN\_LOCAL\_ANALYZER\_INSTALLATION\_DIR}/conf/LanguageInfo.properties and add extensions to 'other' technology: ``other=cls``

1. runs pmd and kiuwan local analizer programs (assuming that pmd 6.12 is used):

	> {pmd\_installation\_dir}\\bin\\pmd.bat -d {src\_dir} -f xml -R {pmd\_installation\_dir\\lib\\pmd-apex-6.12.0\\rulesets\\apex\\ruleset.xml > {src_dir}\pmd-apex-report.xml
	
	> {kiuwan\_local\_analyzer\_installation\_dir}\\bin\\agent.cmd -n {app\_name} -s {src\_dir}



## how to compile
1. From your Kiuwan Local Analyzer installation copy the {KIUWAN\_LOCAL\_ANALYZER\_INSTALLATION\_DIR}/lib.engine/analyzer.jar in pmd-apex-kiuwan-plugin/libext/kiuwan-kla-dependencies/analyzer/0.0.0/analyzer-0.0.0.jar

1. At pmd-apex-kiuwan-plugin directory, run: 
	mvn clean install


## how does it work?
Since the May 2019 version, kiuwan supports a generic technology (language) called 'Other'.
This is a 'dummy' technology that allows users to import in kiuwan defects/vulnerabilities from other tools, for languages that are not natively supported by kiuwan.

There is not 'software metrics', nor 'duplicated code' nor 'CQM software indicators'.

To avoid execution problems when you have another languages in your analysis, 'loc' metric has been replaced by 'lines of text'.


### rule CUS.MCP.KIUWAN.RULES.PMD.APEX.Plugin
This kiuwan plugin is really a kiuwan native rule that looks for a PMD report file (called pmd-apex-report.xml) and generates 'kiuwan defects' for each 'PMD violation' reported in that file.

You need to upload and insert this rule (resources/ruledef/CUS.MCP.KIUWAN.RULES.PMD.APEX.Plugin.rule.xml) in your kiuwan model to ensure that PMD report is processed.

### kiuwan rules vs PMD rules
Also, for each 'PMD rule' you need a kiuwan ruledef, and also upload them to kiuwan.
You can run PMD engine with the full ruleset, but only violations for rules in your kiuwan model will be imported as kiuwan defects.

As example, ruledefs for PMD v6.12, can be found at resources/ruledef/pmd directory.

A Ruledef generator example can be found at src/...

Some considerations for this ruledef files:

1. Criterium 'OPT.CRITERIUM_VALUE.CQM' can take values: MAINTAINABILITY, EFFICIENCY, PORTABILITY, RELIABILITY or SECURITY.

1. Criterium 'OPT.CRITERIUM\_VALUE.VULNERABILITY\_TYPE' is specific for 'kiuwan code security module'. Only rules with this attribute are shown as 'vulnerabilities'. It can take values: BUFFER\_HANDLING, CONTROL\_FLOW\_MANAGEMENT, DESIGN\_ERROR, ENCRYPTION\_AND\_RANDOMNESS, ERROR\_HANDLING\_AND\_FAULT\_ISOLATION, FILE\_HANDLING, INFORMATION\_LEAKS, INITIALIZATION\_AND\_SHUTDOWN, INJECTION, MISCONFIGURATION, NUMBER\_HANDLING, PERMISSIONS\_PRIVILEGES\_AND\_ACCESS\_CONTROLS, POINTER\_AND\_REFERENCE\_HANDLING, SYSTEM\_ELEMENT\_ISOLATION or OTHER.

1. Criterium 'OPT.CRITERIUM\_VALUE.REPAIR\_DIFFICULTY' can take values: VERY\_HIGH, HIGH, MEDIUM, LOW or VERY\_LOW. VERY\_LOW is not used for 'code security' rules.

1. Criterium 'OPT.CRITERIUM\_VALUE.PRIORITY' can take values: VERY\_HIGH, HIGH, MEDIUM, LOW or VERY\_LOW.

1. Values in 'tags' element can be used to filter rules according this values. For example: ``<tags>apex</tags>``

1. Use element 'reference' for additional info. For example: ``<reference><![CDATA[https://pmd.github.io/latest/pmd_rules_apex_security.html#apexbadcrypto/]]></reference>``

1. Use element 'normatives/security' to assign security standards to this rule. For example: ``<normatives><security>CWE:338,OWASP:M2014:M6</security></normatives>``


