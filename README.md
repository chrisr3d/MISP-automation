# MISP-automation
Get started with some ways to automate your MISP operations

## Requirement

- python >= 3.8

## Initializing up your environment

### Getting the required content

```bash
git clone https://github.com/chrisr3d/MISP-automation.git
cd MISP-automation
git submodule update --init --recursive
```

### setting up a virtual environment

(Optional but recommended)

```bash
virtualenv -p python3 venv
source venv/bin/activate
```
(Use `deactivate` to exit from `source` once you are done)

Alternatively you can also prefix all your `python` and `pip` commands with `./venv/bin/` (e.g: `./venv/bin/pip3 install -U pip`)

### Setting up Jupyter

In order to follow along on your computer:

```bash
pip3 install notebook
```

### Installation of the required libraries

#### Requirements

To make sure the package required for pydeep is installed, you should run:
```bash
sudo apt-get install -y libfuzzy-dev
```

Alternatively, if you are a MacOS user, run the following:
```bash
source fixMacOSfuzzy.sh
```

#### Quick install

Once you have the required dependencies, you can install PyMISP, PyMISPGalaxies and PyTaxonomies all at once using the following install script:
```bash
./install.sh
```

#### Detailed install

Alternatively, if you're only interested in one of the libraries, or you want to install them yourself, here is the detailed process from which you can choose the libraries you're interested in:
```bash
pip3 install -e PyMISP

# In order to be able to use the additional PyMISP helpers
pip3 install python-magic lief pydeep2

pip3 install PyMISPGalaxies

pip3 install PyTaxonomies
```

## Usage

You can then run Jupyter and access the notebooks

```bash
cd notebooks
jupyter-notebook
```

Please make sure you installed the python libraries related to the notebook you want to explore
