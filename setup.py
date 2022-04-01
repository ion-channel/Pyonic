from distutils.core import setup
setup(
    name='pyonic',
    packages=['pyonic'],  # Chose the same as "name"
    version='1.0.9',
    license='MIT',
    description='This is a Python SDK for the Ion Channel Application Programming Interface ',
    author='Ion Channel',
    author_email='dev@ionchannel.io',
    url='https://github.com/ion-channel/Pyonic',
    download_url='https://github.com/ion-channel/Pyonic/archive/refs/tags/v1.0.9-alpha.tar.gz',
    keywords=['BuildTools', 'IonChannel'],
    install_requires=[
        'pytest~=7.1.1',
        'PyYAML~=5.4.1',
        'pyonic~=1.0.9',
        'requests~=2.27.1'
    ],
    classifiers=[
        'Development Status :: Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
    ],


)

