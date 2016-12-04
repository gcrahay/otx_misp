
Changelog
=========

1.1 (2016-12-04)
----------------

*  Fix compatibility with PyMISP >= 2.4.53
*  Improve Python 3 support

1.0.3 (2016-09-10)
------------------

*  Fix new configuration cloning bug

1.0.2 (2016-09-02)
------------------

*  Fix compatibility issue with Python 2.7.6

1.0.1 (2016-09-01)
------------------

*  Catch exceptions when disabling SSL warnings

1.0.0 (2016-06-21)
------------------

* First stable version
* Pulse Traffic Light Protocol level added as tag in MISP event
* If the last part of a MISP tag and a Pulse tag are the same, tag the MISP event
* MISP attributes `to_ids` field

0.3.0 (2016-06-20)
------------------

* Fix default handling for distribution, threat_level and analysis parameters
* Better performance: Use OTXv2 generator API and remove some delays

0.2.0 (2016-06-14)
------------------

* Integrate OTXv2 as a subtree.

0.1.0 (2016-06-14)
------------------

* First release on PyPI.
