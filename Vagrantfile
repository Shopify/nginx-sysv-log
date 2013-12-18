# -*- mode: ruby -*-
# vi: set ft=ruby :

ENV['VAGRANT_DEFAULT_PROVIDER'] = 'vmware_fusion'

Vagrant.configure("2") do |config|

  # Name of the box
  config.vm.box = 'precise64'

  # Allow agent forwarding. This allows you to assume the ssh identity of the
  # host on the guest. See the `ssh_agent` plugin.
  config.ssh.forward_agent = true

  # Configure VMware Fusion specific options.
  config.vm.provider :vmware_fusion do |v, override|
    v.vmx['memsize']              = 1024
    v.vmx['numvcpus']             = 2
    v.vmx['vpmc.enable']          = "TRUE"
    v.vmx['cpuid.coresPerSocket'] = 2

    override.vm.box_url ="http://officeserver.localaPublic/Vagrant/ubuntu-12.04_vmware.box"
  end

  config.vm.provision "shell", inline: "" +
    "wget http://nginx.org/download/nginx-1.5.7.tar.gz && " +
    "tar xf nginx-1.5.7.tar.gz"

end
