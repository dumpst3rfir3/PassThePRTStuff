# Pass the PRT Stuff

TL;DR: These 2 tools piggyback on the excellent work from Dirk-jan and Lee Chagolla-Christensen. They are basically just modified versions of [ROADtoken](https://github.com/dirkjanm/ROADtoken) and [RequestAADRefreshToken](https://github.com/leechristensen/RequestAADRefreshToken) that:
- Added the functionality of retrieving a nonce for you
- Involved many minor modifications to avoid detections based on signatures of those 2 tools

**Both tools must be run from an Azure AD-joined device to retrieve a valid, signed JWT.**

## WOAHToken

![](img/woah.jpg)

Usage:
```
.\WOAHtoken.exe [tenant_id]
```

Note: if no tenant ID is passed, it will use a default one of all zero's. If run from an AzureAD-joined machine, you will still get a valid nonce and token (at least at the time of this writing). At some point, a valid tenant ID was required to get a valid nonce, but that doesn't seem to be the case anymore.

## UtahGetMeAnAADToken

![](img/UtahGetMe2.jpg)

Usage:
```
.\UtahGetMeAnAADToken.exe [tenant_id]
```

Note: same as above - if no tenant ID is passed, it will use a default one of all zero's. If run from an AzureAD-joined machine, you will still get a valid nonce and token (at least at the time of this writing). At some point, a valid tenant ID was required to get a valid nonce, but that doesn't seem to be the case anymore.

# References

- https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/
- https://posts.specterops.io/requesting-azure-ad-request-tokens-on-azure-ad-joined-machines-for-browser-sso-2b0409caad30 