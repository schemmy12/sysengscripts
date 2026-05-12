#!/bin/bash

REQUIRED_PRINTERS=(
"LA_-_Copy_Room_-_Konica_C451i_-_53x"
"MP_-_1st_Floor_Copy_Room_-_Konica_C451i"
"MP_-_2nd_Floor_Copy_Room_-_Konica_C451i"
"MP_-_3rd_Floor_Copy_Room_-_Konica_C451i"
"NY_-_11th_Floor_Copy_Room_-_Konica_C451i_-_53x"
"NY_-_12th_Floor_Copy_Room_-_Konica_C451i_-_53x"
"NY___11th_Floor_Copy_Room___Konica_C451i"
"NY___12th_Floor_Copy_Room___Konica_C451i"
"SF_-_Copy_Room_-_Konica_C451i_-_53x"
"SF_-_Expansion_-_Konica_C451i_-_53x"
"SM_-_Copy_Room_-_Konica_C451i_-_53x"
"VA_-_Kitchen_-_Konica_C451i"
)

MISSING=0

for PRINTER in "${REQUIRED_PRINTERS[@]}"; do
    if ! lpstat -p | grep -q "$PRINTER"; then
        MISSING=1
    fi
done

if [ $MISSING -eq 0 ]; then
    echo "<result>Compliant</result>"
else
    echo "<result>Non-Compliant</result>"
fi