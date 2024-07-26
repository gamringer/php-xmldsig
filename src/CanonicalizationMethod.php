<?php

namespace gamringer\xmldsig;

enum CanonicalizationMethod: string
{
	case METHOD_1_0 = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
	case METHOD_1_0_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
	case METHOD_EXCLUSIVE_1_0 = 'http://www.w3.org/2001/10/xml-exc-c14n#';
	case METHOD_EXCLUSIVE_1_0_WITH_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
	//case METHOD_1_1 = 'http://www.w3.org/2006/12/xml-c14n11';
	//case METHOD_1_1_WITH_COMMENTS = 'http://www.w3.org/2006/12/xml-c14n11#WithComments';
}