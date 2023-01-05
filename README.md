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

### Installation of PyMISP

```bash
cd PyMISP
pip3 install -e .

# To make sure the package required for pydeep is installed
sudo apt-get install -y libfuzzy-dev

# In order to be able to use the additional PyMISP helpers
pip3 install python-magic, lief, git+https://github.com/kbandla/pydeep.git
```

### Installation of PyTaxonomies

```bash
pip3 install PyTaxonomies/
```

## Usage

```bash
cd notebooks
jupyter-notebook
```
