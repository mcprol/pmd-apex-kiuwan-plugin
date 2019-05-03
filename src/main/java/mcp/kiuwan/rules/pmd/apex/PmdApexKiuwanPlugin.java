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
 * If source code file is not found, a default text is used in the Kiuwan reports.
 */
public class PmdApexKiuwanPlugin extends AbstractRule { 
	private final static Logger logger = Logger.getLogger(PmdApexKiuwanPlugin.class);

	private String PMD_REPORT_NAME = "pmd-apex-report.xml";
	private String RULECODE_PREFIX = "CUS.OTHER.PMD.APEX.";
	
	private HashMap <String, Rule> kiuwanRulesetMap = new HashMap <String, Rule>();

	public void initialize (RuleContext ctx) { 
		super.initialize(ctx);	
		File baseDir = ctx.getBaseDirs().get(0);
		logger.debug("initialize: " +  this.getName() + " : " + baseDir);
		
		// Read list of Kiuwan rules into memory as not to access them for every violation
		int startPos = RULECODE_PREFIX.length();
		Iterator<Rule> it = ctx.getRules().getRules();
		while (it.hasNext()) {
			Rule rule = (Rule) it.next();
			String kiuwanRuleName = rule.getName().toLowerCase();
			if (kiuwanRuleName.startsWith(RULECODE_PREFIX.toLowerCase())) {
				String pmdRuleName = kiuwanRuleName.substring(startPos).toLowerCase();
				kiuwanRulesetMap.put(pmdRuleName, rule);
				logger.debug("added rule to map: " + pmdRuleName);
			}
		}
	}

	protected void visit (BaseNode root, final RuleContext ctx) { 
		// this method is run once for each source file under analysis.
		// this method is left in blank intentionally.
	}

	public void postProcess (RuleContext ctx) { 
		// this method is run once for analysis
		super.postProcess(ctx); 
		logger.info("postProcess: " +  this.getName());

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

	private void processReportFileSax(RuleContext ctx, Path p) throws ParserConfigurationException, SAXException, IOException {
		logger.info("processing: " +  p);

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

		private boolean inFoundFile = false;
		private boolean inMethod = false;
		private String fileName = "";
		private String ruleName = "";
		private int beginLine = 0;

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
			if (qName.equalsIgnoreCase("file")) {					// Only process <class> where sourcefilename is found
				fileName = attributes.getValue("name");
				logger.debug("PmdApexReportHandler.startElement(file" + ", "+ fileName + ")");
				inFoundFile = true;
			} else if (inFoundFile && qName.equalsIgnoreCase("violation")) {
				String sBeginLine  = attributes.getValue("beginline");
				beginLine = Integer.valueOf(sBeginLine);
				ruleName = attributes.getValue("rule");
				logger.debug("PmdApexReportHandler.startElement(violation" + ", " + beginLine);
				inMethod = true;
			}
		}

		@Override
		public void endElement(String uri, String localName, String qName) throws SAXException {
			if (qName.equalsIgnoreCase("file")) {
				inFoundFile = false;
				logger.debug("PmdApexReportHandler.endElement(file)");
			} 
		}

		public void characters(char[] ch, int start, int length) throws SAXException {
			if (inMethod) {
				String defect = new String(ch, start, length).trim();	 
				inMethod  = false;
				logger.debug("PmdApexReportHandler.characters, " + ruleName + ", " + fileName + ", " + beginLine + ", " + defect);
				
				// Does the rule exist in the Kiuwan model? 
				if (kiuwanRulesetMap.containsKey(ruleName)) {
					Rule rule = kiuwanRulesetMap.get(ruleName);
					File file = new File(fileName);
					ctx.setSourceCodeFilename(file.toPath().toFile());
					logger.debug("PmdApexReportHandler.characters, Rule used: " + rule.getName());
					
					// Look up text of beginline of violation at file indicated in tag <file name=... />
					// If source code file is not found, a default text is used in Kiuwan.
					String[] lines = null;
					String line = "Source code not available.";
					try {
						 lines = IOUtils.lines(file);
						 line = lines[beginLine - 1];
					} catch (Exception e) {
						logger.warn("PmdApexReportHandler: Cannot open source file: " + fileName, e);
					}
					
					RuleViolation rv = new RuleViolation(rule, beginLine, file);
					if (lines != null) {
						rv.setCodeViolated(line);
					}
					ctx.getReport().addRuleViolation(rv);
				}
			}
		}
	}	
}



