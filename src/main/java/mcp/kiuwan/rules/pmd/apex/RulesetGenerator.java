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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class RulesetGenerator {
	
	private static final String PMD_HOME = "D:/pmd-bin-6.12.0";
	private static final String PMD_RULESET_DIR = PMD_HOME + "/lib/pmd-apex-6.12.0/category/apex";
	private static final String RULEDEF_DIR= "D:/pmd-apex-kiuwan-ruledef";
	private static final String RULEDEF_TEMPLATE= "/ruledef/template/CUS.OTHER.PMD.APEX.template.rule.xml";
	
	public static void main(String[] args) throws IOException {
		log("Running RulesetGenerator...");
		
		Files.list(Paths.get(PMD_RULESET_DIR))
			.filter(Files::isRegularFile)
			.filter(p -> p.toFile().getName().endsWith("xml"))
			.forEach(p -> parseRuleset(p));
	}
	
	
	private static void parseRuleset(Path ruleset) {
		try {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(ruleset.toFile());
			doc.getDocumentElement().normalize();
			
			Element rulesetNode = doc.getDocumentElement();
			String rulesetName = rulesetNode.getAttribute("name");
			
			NodeList nList = doc.getElementsByTagName("rule");
			for (int i=0; i<nList.getLength(); i++ ) {
				Node node = nList.item(i);
				if (node.getNodeType() == Node.ELEMENT_NODE) {
					generateRuledef(rulesetName, (Element)node);
				}				
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	private static void generateRuledef(String rulesetName, Element ruleNode) throws IOException {
		String rulecode = ruleNode.getAttribute("name");
		String rulename = ruleNode.getAttribute("message");
		String reference = ruleNode.getAttribute("externalInfoUrl");
		String description = ruleNode.getElementsByTagName("description").item(0).getTextContent();
		String example = ruleNode.getElementsByTagName("example").item(0).getTextContent();
		
		String category = "MAINTAINABILITY";
		String vulnerability_type = "";
		if ("SECURITY".equalsIgnoreCase(rulesetName.toUpperCase())) {
			category = "SECURITY";
			vulnerability_type = "<criterium-value ref=\"OPT.CRITERIUM_VALUE.VULNERABILITY_TYPE.OTHER\"/>";
		}
		
		Map<String, String> priorityMap = Stream.of(new String[][] {
			{ "1", "VERY_HIGH"}, 
			{ "2", "HIGH" }, 
			{ "3", "MEDIUM" }, 
			{ "4", "LOW" }, 
			{ "5", "VERY_LOW" }, 
			}).collect(Collectors.toMap(data -> data[0], data -> data[1]));		
		String priority = ruleNode.getElementsByTagName("priority").item(0).getTextContent();

		String ruledefFileName = RULEDEF_DIR + "/" + PmdApexKiuwanPlugin.RULECODE_PREFIX  + rulecode + ".rule.xml";
		log("Generate " + ruledefFileName);
		
		String template = readTemplateRuledef();
				
		template = template.replace("@rulecode@", rulecode);
		template = template.replace("@reference@", reference);
		template = template.replace("@rulename@", rulename);
		template = template.replace("@description@", description);
		template = template.replace("@example@", example);
		template = template.replace("@priority@", priorityMap.get(priority));
		template = template.replace("@category@", category);
		template = template.replace("@vulnerability_type@", vulnerability_type);
			
	    Path path = Paths.get(ruledefFileName);
	    Files.write(path, template.getBytes());
	}

	
	private static String readTemplateRuledef() throws IOException {
		String template = "";
		
		InputStream is = RulesetGenerator.class.getResourceAsStream(RULEDEF_TEMPLATE);
	    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
	    int nRead;
	    byte[] data = new byte[1024];
	    while ((nRead = is.read(data, 0, data.length)) != -1) {
	        buffer.write(data, 0, nRead);
	    }	 
	    buffer.flush();
	    
	    byte[] byteArray = buffer.toByteArray();
	    template = new String(byteArray);
	    
	    buffer.close();
	    is.close();
	    
	    return template;
	}


	private static void log(String msg) {
		System.out.println(msg);
	}

}
