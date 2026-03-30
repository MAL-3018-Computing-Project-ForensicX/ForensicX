rule RansomNote_strings { 
    strings:
        $a1 = "HOW TO RECOVER YOUR FILES" nocase
        $a2 = "YOUR FILES ARE ENCRYPTED" nocase
        $a3 = "Bitcoin" nocase
        $a4 = ".locked" nocase
    condition:
        any of them 
}