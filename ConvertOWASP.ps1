function ConvertOWASP-MDtoYAML{
    Param()
    1..10 | %{
        ## Parse from bottom
        $MD = ((gc "A$_.md" -Encoding UTF8)-join"`r`n")
        ## List of Mapped CWEs
        $CWE = (($MD-split"## List of Mapped CWEs")[1]).trim()
        $MD  = (($MD-split"## List of Mapped CWEs")[0]).trimEnd()
        ## References
        $Ref = (($MD-split"## References")[1]).trim()
        $MD  = (($MD-split"## References")[0]).trimEnd()
        ## Example Attack Scenarios
        $Exa = (($MD-split"## Example Attack Scenarios")[1]).trim()
        $MD  = (($MD-split"## Example Attack Scenarios")[0]).trimEnd()
        ## How to Prevent
        $Prv = (($MD-split"## How to Prevent")[1]).trim()
        $MD  = (($MD-split"## How to Prevent")[0]).trimEnd()
        ## Description
        $Dsc = (($MD-split"## Description")[1]).trim()
        $MD  = (($MD-split"## Description")[0]).trimEnd()
        ## Overview
        $Ovr = (($MD-split"## Overview")[1]).trim()
        $MD  = (($MD-split"## Overview")[0]).trimEnd()
        ## Factors
        $Fct = (($MD-split"## Factors")[1]).trim()
        $MD  = (($MD-split"## Factors")[0]).trimEnd()
        # ID/Name
        $Ttl = (($MD-split'!\[icon\]')[0]).trimEnd().TrimStart("# ")
        $UID = ($Ttl-split$([char]8211))[0].trim()
        $Nme = ($Ttl-split$([char]8211))[1].trim()
        ## Reformat
        # Factors
        $Fctsp = (($fct-split"`r`n")-ne'')[-1]-split'\|'
        $fct   = [PSCustomObject]@{
            CWE             = $Fctsp[1].trim()-as[Int]
            IncidenceMaxPct = $Fctsp[2].trim().trimend('%')-as[float]
            IncidenceAvgPct = $Fctsp[3].trim().trimend('%')-as[float]
            ExploitAvg      = $Fctsp[4].trim()-as[float]
            ImpactAvg       = $Fctsp[5].trim()-as[float]
            CoverageMaxPct  = $Fctsp[6].trim().trimend('%')-as[float]
            CoverageAvgPct  = $Fctsp[7].trim().trimend('%')-as[float]
            CVE             = $Fctsp[8].trim()-as[int]
            }
        # Reference
        $Refsp = (($Ref-split"`r`n")-ne"")|%{$_.trimStart("-   \[").trimEnd(")")}
        $ref = Foreach($lnk in @($Refsp)){
            [PSCustomObject]@{
                Title = $(if($lnk -match "\]\("){($lnk-split"\]\(")[0]}else{$_})
                Url   = $(if($lnk -match "\]\("){($lnk-split"\]\(")[1]}else{})
                }
            }
        # CWE
        $CWEsp = ((($CWE-split"`r`n")-ne"")|%{$_.trimStart("\[").trimEnd(")")})
        $CWE = Foreach($lnk in @($CWEsp)){
            $Title = ($lnk-split"\]\(")[0]
            $Url   = ($lnk-split"\]\(")[1]
            $Null = $title -match "(CWE-.*\d)"
            $ID = ($Matches[0]-split" ")[0]
            $Title = ($title-replace"CWE-.*\d ",'').trim()
            [PSCustomObject]@{
                ID    = $ID
                Title = $Title.trimStart("- ")
                Url   = $Url
                }
            }
        ## Output Object
        [PSCustomObject]@{
            ID          = $UID
            Name        = $Nme
            Overview    = $Ovr
            Factors     = $fct
            Description = $Dsc
            Prevention  = $Prv
            Example     = $Exa
            Reference   = $Ref
            CWE         = $CWE
            }
        }
    }