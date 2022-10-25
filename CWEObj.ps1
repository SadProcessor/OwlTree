## CWEOwl
#
# Site
# https://cwe.mitre.org/
#
# DL
# https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
#
# Blog info
# https://medium.com/@CWE_CAPEC/the-missing-piece-in-vulnerability-management-c8c7c0e55e5f

<#
$CWERaw   = ([xml](gc "C:\Users\SadProcessor\Documents\Stuff\cwec_v4.8.xml")).weakness_catalog
$CWE_Weak = $CWERaw.weaknesses.weakness | ? status -ne deprecated
$CWE_Ref  = $CWERaw.external_references.External_Reference
#>

<#
#Abstraction
#Affected_Resources
#Alternate_Terms
#Applicable_Platforms
#Background_Details
#Common_Consequences
#Content_History
#Demonstrative_Examples
 #Description
#Detection_Methods
 #Extended_Description
#Functional_Areas
 #ID
#Likelihood_Of_Exploit
#Modes_Of_Introduction
 #Name
#Notes
#Observed_Examples
#Potential_Mitigations
References
 #Related_Attack_Patterns
 #Related_Weaknesses
#Status
Structure
Taxonomy_Mappings
Weakness_Ordinalities
#>
$CWE = Foreach($Obj in $CWE_weak){
    [PSCustomObject]@{
        ID = "CWE-$($Obj.id)"
        Name = $Obj.name
        Alias = $Obj.Alternate_Terms.alternate_term | %{$_|select term,description}
        Description = $Obj.Description
        Extended = $Obj.Extended_description | %{if($_.'P'){$_.'P'-join"`r`n"}else{$_}}
        Related = $Obj.Related_Weaknesses.Related_Weakness | %{$_|Select Nature,CWE_ID}
        CAPEC = $Obj.Related_Attack_Patterns.Related_Attack_Pattern |%{$_|select CAPEC_ID}
        Abstraction = $Obj.Abstraction
        AffectedResources = $Obj.Affected_Resources.Affected_Resource
        Platform = $Obj.Applicable_Platforms.language | %{$_|Select name,prevalence}
        Details = $Obj.Background_Details.Background_Detail
        Consequences = $Obj.Common_Consequences.consequence | %{$_|Select Scope,Impact,Note}
        Examples = $Obj.Demonstrative_Examples.Demonstrative_Example | %{[PSCustomObject]@{
            ID    = $_.Demonstrative_Example_ID
            Intro = $_.Intro_text
            Code  = $_.Example_Code | %{[PSCustomObject]@{Language=$_.Language;Code=$_.div.'#text'}}
            Text  = $_.Body_Text
            }}
        Detection = $Obj.Detection_Methods.Detection_Method | %{[PSCustomObject]@{
            ID = $_.Detection_Method_ID
            Method = $_.Method
            Description = $_.Description
            Effectiveness = $_.Effectiveness
            Notes = $_.Effectiveness_notes
            }}
        FunctionalArea = $Obj.Functional_Areas.functional_Area
        ExploitLikelihood = $Obj.Likelihood_Of_Exploit  
        IntroductionMode = ($Obj.Modes_Of_Introduction.Introduction).phase
        Observation = $Obj.Observed_Examples.Observed_Example | %{$_|select Reference,description,link}
        Mitigation = $Obj.Potential_Mitigations.Mitigation | %{[PSCustomObject]@{
            ID = $_.Mitigation_ID
            Phase = $_.Phase
            Strategy = $_.Strategy
            Description = $_.Description
            Effectiveness = $_.Effectiveness
            Notes = $_.Effectiveness_Notes
            }}
        Mapping = $Obj.Taxonomy_Mappings.Taxonomy_Mapping | %{[PSCustomObject]@{
            Taxonomy = $_.Taxonomy_Name
            ID       = $_.Entry_ID
            Name =   $_.Entry_Name
            }}
        #Ordinality = $Obj.Weakness_Ordinalities.Weakness_Ordinality
        Ref = $Obj.References.Reference.External_Reference_ID
        Structure = $Obj.Structure
        Status = $Obj.status
        Notes = $Obj.Notes.note | %{[PSCustomObject]@{Type=$_.Type;Text=$_.'#text'}}
        #History = $Obj.Content_History
        }
    }

    $REF = $CWE_ref|%{[PSCustomObject]@{
        ID = $_.Reference_ID
        Title = $_.Title
        Author = $_.Author
        URL = $_.URL
        }}
    #[PSCustomObject]@{CWE=$CWE;REF=$REF}|Convertto-json -Depth 7 -Compress|out-file ./CWEObj.json -Force