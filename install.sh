# Additional libraries to be able to use some of the PyMISP helpers
pip3 install python-magic lief pydeep2

# PyMISP
pushd PyMISP
pip3 install -e .
popd

# PyTaxonomies
pushd PyTaxonomies
pip3 install .
popd

# PyMISPGalaxies
pushd PyMISPGalaxies
pip3 install .
popd
