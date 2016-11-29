// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package builtin

import (
	"bytes"

	"github.com/snapcore/snapd/interfaces"
)

var telephonyPermanentSlotAppArmor = []byte(`
# Description: Allow operating as the telephony service. Reserved because this
#  gives privileged access to the system.
# Usage: reserved

# DBus accesses
#include <abstractions/dbus-session-strict>
dbus (send)
	bus=session
	path=/org/freedesktop/DBus
	interface=org.freedesktop.DBus
	member={Request,Release}Name
	peer=(name=org.freedesktop.DBus),

dbus (send)
	bus=session
	path=/org/freedesktop/*
	interface=org.freedesktop.DBus.Properties
	peer=(label=unconfined),

# Allow services to communicate with each other
dbus (receive, send)
	peer=(label="snap.@{SNAP_NAME}.*"),

# Allow binding the service to the requested connection name
dbus (bind)
	bus=session
	name="com.canonical.TelephonyServiceIndicator",
dbus (bind)
	bus=session
	name="org.freedesktop.Telepathy.Client.TelephonyServiceIndicator",
dbus (bind)
	bus=session
	name="com.canonical.Approver",
dbus (bind)
	bus=session
	name="org.freedesktop.Telepathy.Client.TelephonyServiceApprover",
dbus (bind)
	bus=session
	name="com.canonical.TelephonyServiceHandler",
dbus (bind)
	bus=session
	name="org.freedesktop.Telepathy.Client.TelephonyServiceHandler",
dbus (bind)
	bus=session
	name="org.freedesktop.Telepathy.Client.TelephonyServiceObserver",

########################
# Telepathy
########################
dbus (receive, send)
	bus=session
	path=/org/freedesktop/Telepathy,
dbus (receive, send)
	bus=session
	path=/org/freedesktop/Telepathy/Client,
dbus (receive, send)
	bus=session
	path=/org/freedesktop/Telepathy/Client/TelephonyServiceIndicator,
dbus (receive, send)
	bus=session
	path=/org/freedesktop/Telepathy/Client/TelephonyServiceApprover,
dbus (receive, send)
	bus=session
	path=/org/freedesktop/Telepathy/Client/TelephonyServiceHandler,
dbus (receive, send)
	bus=session
	path=/org/freedesktop/Telepathy/Client/TelephonyServiceObserver,
dbus (receive, send)
	bus=session
	path=/org/freedesktop/Telepathy/AccountManager,
`)

var telephonyConnectedPlugAppArmor = []byte(`
# Description: Can access the telephony-service. This policy group is reserved
#  for vetted applications only in this version of the policy. A future
#  version of the policy may move this out of reserved status.
# Usage: reserved

#include <abstractions/dbus-session-strict>

dbus (receive, send)
    bus=session
    peer=(label=###SLOT_SECURITY_TAGS###),
dbus (send)
    bus=session
    path=/com/canonical/TelephonyServiceIndicator
    peer=(name=com.canonical.TelephonyServiceIndicator,label=unconfined),
dbus (receive)
    bus=session
    path=/com/canonical/TelephonyServiceIndicator
    peer=(label=unconfined),
dbus (send)
    bus=session
    path=/com/canonical/TelephonyServiceIndicator/**
    peer=(name=com.canonical.TelephonyServiceIndicator,label=unconfined),
dbus (receive)
    bus=session
    path=/com/canonical/TelephonyServiceIndicator/**
    peer=(label=unconfined),
dbus (send)
    bus=session
    path=/com/canonical/Approver
    peer=(name=com.canonical.Approver,label=unconfined),
dbus (receive)
    bus=session
    path=/com/canonical/Approver
    peer=(label=unconfined),
dbus (send)
    bus=session
    path=/com/canonical/Approver/**
    peer=(name=com.canonical.Approver,label=unconfined),
dbus (receive)
    bus=session
    path=/com/canonical/Approver/**
    peer=(label=unconfined),
dbus (send)
    bus=session
    path=/com/canonical/TelephonyServiceHandler
    peer=(name=com.canonical.TelephonyServiceHandler,label=unconfined),
dbus (receive)
    bus=session
    path=/com/canonical/TelephonyServiceHandler
    peer=(label=unconfined),
dbus (send)
    bus=session
    path=/com/canonical/TelephonyServiceHandler/**
    peer=(name=com.canonical.TelephonyServiceHandler,label=unconfined),
dbus (receive)
    bus=session
    path=/com/canonical/TelephonyServiceHandler/**
    peer=(label=unconfined),
dbus (send)
    bus=session
    path=/com/canonical/TelephonyServiceObserver
    peer=(name=com.canonical.TelephonyServiceObserver,label=unconfined),
dbus (receive)
    bus=session
    path=/com/canonical/TelephonyServiceObserver
    peer=(label=unconfined),
dbus (send)
    bus=session
    path=/com/canonical/TelephonyServiceObserver/**
    peer=(name=com.canonical.TelephonyServiceObserver,label=unconfined),
dbus (receive)
    bus=session
    path=/com/canonical/TelephonyServiceObserver/**
    peer=(label=unconfined),
`)

var telephonyPermanentSlotSecComp = []byte(`
# Description: Allow operating as the telephony service. Reserved because this
# gives
#  privileged access to the system.
# Usage: reserved
accept
accept4
bind
connect
getpeername
getsockname
getsockopt
listen
recv
recvfrom
recvmmsg
recvmsgj
send
sendmmsg
sendmsg
sendto
setsockopt
shutdown
socketpair
socket
`)

var telephonyConnectedPlugSecComp = []byte(`
# Description: Allow using telephony service. Reserved because this gives
#  privileged access to the telephony service.
# Usage: reserved

# Can communicate with DBus system service
connect
getsockname
recv
recvmsg
send
sendto
sendmsg
socket
`)

var telephonyPermanentSlotDBus = []byte(`
<policy user="root">
    <allow own="com.canonical.TelephonyServiceIndicator"/>
	<allow own="org.freedesktop.Telepathy.Client.TelephonyServiceIndicator"/>
	<allow own="com.canonical.Approver"/>
	<allow own="org.freedesktop.Telepathy.Client.TelephonyServiceApprover"/>
	<allow own="com.canonical.TelephonyServiceHandler"/>
	<allow own="org.freedesktop.Telepathy.Client.TelephonyServiceHandler"/>
	<allow own="org.freedesktop.Telepathy.Client.TelephonyServiceObserver"/>
   	<allow send_destination="com.canonical.TelephonyServiceIndicator"/>
	<allow send_destination="org.freedesktop.Telepathy.Client.TelephonyServiceIndicator"/>
	<allow send_destination="com.canonical.Approver"/>
	<allow send_destination="org.freedesktop.Telepathy.Client.TelephonyServiceApprover"/>
	<allow send_destination="com.canonical.TelephonyServiceHandler"/>
	<allow send_destination="org.freedesktop.Telepathy.Client.TelephonyServiceHandler"/>
	<allow send_destination="org.freedesktop.Telepathy.Client.TelephonyServiceObserver"/>
    <allow send_interface="org.freedesktop.DBus.ObjectManager"/>
    <allow send_interface="org.freedesktop.DBus.Properties"/>
</policy>
<policy context="default">
    <deny send_destination="com.canonical.TelephonyServiceIndicator"/>
    <deny send_destination="com.canonical.Approver"/>
    <deny send_destination="com.canonical.TelephonyServiceHandler"/>
</policy>
`)

type TelephonyInterface struct{}

func (iface *TelephonyInterface) Name() string {
	return "telephony"
}

func (iface *TelephonyInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	return nil, nil
}

func (iface *TelephonyInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		old := []byte("###SLOT_SECURITY_TAGS###")
		new := slotAppLabelExpr(slot)
		snippet := bytes.Replace(telephonyConnectedPlugAppArmor, old, new, -1)
		return snippet, nil
	case interfaces.SecuritySecComp:
		return telephonyConnectedPlugSecComp, nil
	}
	return nil, nil
}

func (iface *TelephonyInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		return telephonyPermanentSlotAppArmor, nil
	case interfaces.SecuritySecComp:
		return telephonyPermanentSlotSecComp, nil
	case interfaces.SecurityDBus:
		return telephonyPermanentSlotDBus, nil
	}
	return nil, nil
}

func (iface *TelephonyInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	return nil, nil
}

func (iface *TelephonyInterface) SanitizePlug(plug *interfaces.Plug) error {
	return nil
}

func (iface *TelephonyInterface) SanitizeSlot(slot *interfaces.Slot) error {
	return nil
}

func (iface *TelephonyInterface) LegacyAutoConnect() bool {
	return false
}

func (iface *TelephonyInterface) AutoConnect(*interfaces.Plug, *interfaces.Slot) bool {
	// allow what declarations allowed
	return true
}
