// MIT License
//
// Copyright (c) 2018 Marcos Cacabelos Prol
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package mcp.kiuwan.rules.pmd.apex;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.log4j.Logger;
import org.xml.sax.Attributes;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.als.core.AbstractRule;
import com.als.core.Rule;
import com.als.core.RuleContext;
import com.als.core.RuleViolation;
import com.als.core.ast.BaseNode;
import com.als.core.io.IOUtils;


/**
 * This rule loads PMD Apex report and generates Kiuwan defects/vulnerabilities for each PMD violation.
 * It also looks up the source code text of the beginline of the violation. For this the source code needs to be there where is says in apex.xml, 
 * tag <file name=...
 * If source code file is not found, a default text is used.
 */
public class PmdApexKiuwanPlugin extends AbstractRule { 
	private final static Logger logger = Logger.getLogger(PmdApexKiuwanPlugin.class);

	public final static String RULECODE_PREFIX = "CUS.OTHER.PMD.APEX.";
	private final static String PMD_REPORT_NAME = "pmd-apex-report.xml";
	private final static String DEFAULT_CODE_FRAGMENT = "Source code not available.";
	
	private HashMap <String, Rule> kiuwanRulesetMap = new HashMap <String, Rule>();

	public void initialize (RuleContext ctx) { 
		super.initialize(ctx);	
		File baseDir = ctx.getBaseDirs().get(0);
		logger.debug("initialize: " +  this.getName() + " : " + baseDir);
		
		loadRulesMap(ctx);
	}


	protected void visit (BaseNode root, final RuleContext ctx) { 
		// this method is run once for each source file under analysis.
		// this method is left in blank intentionally.
	}

	
	public void postProcess (RuleContext ctx) { 
		// this method is run once for analysis
		super.postProcess(ctx); 
		logger.info("postProcess rule: " +  this.getName());

		// basedir.
		File baseDir = ctx.getBaseDirs().get(0);

		// iterates over reports files.
		try {
			Files.walk(Paths.get(baseDir.getAbsolutePath()))
			.filter(Files::isRegularFile)
			.filter(p -> p.getFileName().toString().equals(PMD_REPORT_NAME))
			.forEach(p -> {
				try {
					processReportFileSax(ctx, p);
				} catch (ParserConfigurationException | SAXException | IOException e) {
					logger.error("Error parsing file " + p.getFileName() + ". ", e);
				}
			});
		} catch (IOException e) {
			logger.error("", e);
		}
	}

	
	/**
	 * Read list of Kiuwan rules into memory as not to access them for every violation
	 */
	private void loadRulesMap(RuleContext ctx) {
		logger.debug("Creating map for APEX rules in kiuwan ruleset");
		int startPos = RULECODE_PREFIX.length();
		Iterator<Rule> it = ctx.getRules().getRules();
		while (it.hasNext()) {
			Rule rule = (Rule) it.next();
			String kiuwanRuleName = rule.getName();
			logger.debug("Validating " + kiuwanRuleName);
			String pmdRuleName = kiuwanRuleName.substring(startPos);
			if (kiuwanRuleName.startsWith(RULECODE_PREFIX)) {
				kiuwanRulesetMap.put(pmdRuleName, rule);
				logger.debug("added rule to map: " + pmdRuleName);
			} else {
				logger.debug("PMD rule " + pmdRuleName + " not found in kiuwan ruleset");
			}
		}
	}

	
	private void processReportFileSax(RuleContext ctx, Path p) throws ParserConfigurationException, SAXException, IOException {
		logger.info("processing PMD report file: " +  p);

		SAXParserFactory factory = SAXParserFactory.newInstance();
		factory.setNamespaceAware(true);
		factory.setValidating(false);
		SAXParser parser = factory.newSAXParser();

		PmdApexReportHandler handler = new PmdApexReportHandler(ctx);
		parser.parse(p.toFile(), handler);
	}

	
	/**
	 * The PMD APEX xml report handler
	 */
	class PmdApexReportHandler extends DefaultHandler {
		private RuleContext ctx;
		private Locator locator = null;

		private boolean inTagFile = false;
		private boolean inTagViolation = false;
		
		private String attFileName = "";
		private int attViolationBeginLine = 0;
		private int attViolationEndLine = 0;
		private String attViolationRule = "";

		public PmdApexReportHandler(RuleContext ctx) {
			super();
			this.ctx = ctx;

			this.setDocumentLocator(locator);
		}

		
		public void setDocumentLocator(Locator locator) {
			this.locator = locator;
		}

		
		@Override
		public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
			if (qName.equalsIgnoreCase("file")) {
				attFileName = attributes.getValue("name");
				inTagFile = true;
				logger.debug("PmdApexReportHandler.startElement: file, " + attFileName);
			} else if (inTagFile && qName.equalsIgnoreCase("violation")) {
				attViolationBeginLine = Integer.valueOf(attributes.getValue("beginline"));
				attViolationEndLine = Integer.valueOf(attributes.getValue("endline"));
				attViolationRule = attributes.getValue("rule");
				inTagViolation = true;
				logger.debug("PmdApexReportHandler.startElement: violation, " + attViolationRule + ", " + attViolationBeginLine);
			}
		}

		
		@Override
		public void endElement(String uri, String localName, String qName) throws SAXException {
			if (qName.equalsIgnoreCase("file")) {
				inTagFile = false;
				logger.debug("PmdApexReportHandler.endElement: file");
			} 
		}

		
		@Override
		public void characters(char[] ch, int start, int length) throws SAXException {
			if (inTagViolation) {
				String explanation = new String(ch, start, length).trim();	 
				inTagViolation  = false;
				logger.debug("PmdApexReportHandler.characters: " + attFileName + ", " + attViolationRule + ", " + attViolationBeginLine + ", " + explanation);
				
				// Does the rule exist in the Kiuwan model? 
				if (kiuwanRulesetMap.containsKey(attViolationRule)) {
					Rule rule = kiuwanRulesetMap.get(attViolationRule);

					File file = new File(attFileName);
					ctx.setSourceCodeFilename(file.toPath().toFile());
					
					logger.debug("Creating new kiuwan defect for rule: " + rule.getName());
					RuleViolation rv = new RuleViolation(rule, attViolationBeginLine, file);
					
					String fragment = getCodeFragment(file);
					rv.setCodeViolated(fragment);
					rv.addExplanation(explanation);

					ctx.getReport().addRuleViolation(rv);
				} else {
					logger.debug("PMD rule " + attViolationRule + " not found in kiuwan ruleset");
				}
			}
		}

		
		/**
		 * Look up text of beginline of violation at file indicated in tag <file name=... />
		 * If source code file is not found, a default text is used.
		 */
		private String getCodeFragment(File file) {
			String fragment = DEFAULT_CODE_FRAGMENT;

			try {
				String[] lines = IOUtils.lines(file);
				 if (lines.length > 0) {
					 String[] fragmentLines = Arrays.copyOfRange(lines, attViolationBeginLine-1, attViolationEndLine-1+1);
					 fragment = String.join("\n", fragmentLines);						 
				 }
			} catch (Exception e) {
				logger.warn("PmdApexReportHandler: error reading source file: " + attFileName, e);
			}
			
			return fragment;
		}
	}	
}



