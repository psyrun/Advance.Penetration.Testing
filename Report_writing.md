**Report Writing

	GOALS:
		Discuss the importance of the report
		Common mistakes
		Components of the report
		
	Why 
		outcome you can deliver to a client
		Documents the discovery and the remediation plan to the client
		Explains the process followed and assists the client in understanding how they can reduce their risk
		Provide the proritization of corrections for the clients assets
	
	Management
		Want to know if they are secure
		Who is involved when something is found
			We never criticize people just policy 
		Prioritized corrections
			what needs to be fixed first
		Speak in terms, metrics, risk mitigation and money loss
			Graphics and statics work best here
		Technicians 
			Responsible for the fixed
			Recommendations have to be concise
			Describe the steps of remediation
			Prioritized list of corrections
		Developer 
			technically detailed so they can fix the code
			Best when a code review is included in the scope
				Details of the weakness if possible
			Provide attack scenarios to enhance the remediation requirements
			Risk related data tot include prioritization by severity and required remediations
				Include efforts estimations if available
		Common Mistakes
			Not understanding what you are getting
			Not asking for a retest
			Not asking for a letter of attestation
			Using a vendor without a documented process
			Not receiveing guidance on the type of test to receive
			Not asking for a detailed debrief or report walk through
			Not asking for a report with detailed steps and reproducible results
		What are you getting
			Highly dicounted pentest is normally just a vulnerability assessment
			Penetration test includes multipile tests methods with different tools as well as manual validations
			Use minimum two tools when testing
		Retest
			Imperative to test remediation of the findings to validate the risk has been mitigateed
			Not uncommon for a mistake to be made in the remediation steps that prevents the ristk from being mitigated effectively
		Letter of Attestation
			Provides sani6tized proof the test has been performed
			Highlights the results and findings of the test
			After following the test recommendations the site should have eliminated the significant findings
			Validates the site has had a test by an independent 3rd party
		Vendor Process
			Any vendor should be able to list the steps in their proceess and explain details of each steps
			Clearly defined rules of engagement guidance
			listing of authorization forms and templates
		Providing Guidance
			Explaining a blackbox penetration test and the data for it
			Recommending a gray box test to cover the required user level access for application testing 
			During the site "scope" discussion, the specific types of testing and the data requirements from the site shall be determined
		Need for a report	
			The report is the show case it explains what was done and how
			Should provide the organization a view of their risk
			All reports should provide guidance to improve the clients security process
			Hacking into the system is not enough being able to explain the process step by step and recommend how to remove or mitigate the risk is essential
				
		Report Components
			Cover page and change page
				It includes the report title and details abluut the author and client organization
			Change
				This is a record of all the version control tracked changes made on the report including  the names of people who made revisions, when they were made and what edits they made
			Executive summary 
				One page in length is the target
				Assessment findings
				Recommendations on how to remediate risks (risk mitigation strategy)
							
			host table
				Listing of the hosts and targets that were assessed
				Severity ratings for each discovered targets
					ideally sorted by priority for remediation
				Role of the target within the organization when identified
					Domain controller
					Databases
					etc
					
			summary of findings
				A listing of the findings that contins
					finding number 
					servity 
					brief description of the findingAsset that is impacted
					page number to the detailed finding data
					
			detailed findings
				A detailed explanation of each finding consisting of 
					finding number 
					servity 
					descriptipon
					analysis/exposure(research on the specifics of the finding)
					Recommendations (if patch you can suggest patch)
					Assest
			
				Example 
					Description
					Analysis/exposure
					servity
					Recommendations
		
			conclusion
				This is a synopsis of the characterstics and components that were discovered during testing
				Dont make it a sales pitch
				Provide guidance for remediation and steps for security baselines
					Compliance for minimum security baselines
						center for insternet security
							www.cisecurity.organization
							
			Appendices
				Tools used 
				exploitation with screenshots
				servity
				output of the tools used during testing
				Detailed remediation plan when within scope
			
			Magic Tree
				for nmap
			
			Keep notes
				
		
		
	
		
		
		