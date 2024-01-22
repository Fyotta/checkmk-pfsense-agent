<?php

/*
 * Checkmk special agent for pfSense - Fyotta (https://github.com/Fyotta/checkmk-pfsense-agent)
 * 
 * This extension is distributed under the terms of the GNU General Public License, version 3 (GPLv3).
 * See the LICENSE file for details on the license terms.
 *
 * This extension is a standalone work and is not affiliated with or endorsed by pfSense.
 * pfSense is licensed under the Apache License 2.0.
 *
 * Part of this code has been adapted or derived from the original pfSense page.
 * Refer to the pfSense documentation for information on the license and original source code.
*/

// Based on: pfSense 2.7.2 (FreeBSD 14.0)

require_once("ipsec.inc");
require_once("service-utils.inc");
require_once("auth.inc");

function get_ipsec_status() {
	global $config;

    $data = array();

	if (!ipsec_enabled()) {
		$data["ipsec_status"] = "IPsec is disabled";
        $error = array();
        $error["error"] = $data;
        $error["status_code"] = 404;
		return $error;
	}
	if (!get_service_status(array('name' => 'ipsec'))) {
		$data["ipsec_status"] = "IPsec daemon is stopped";
        $error["error"] = $data;
        $error["status_code"] = 500;
		return $error;
	}

	$cmap = ipsec_map_config_by_id();
	$status = ipsec_list_sa();

	$p1conids = array_column($status, 'con-id');
	$p1uniqueids = array_column($status, 'uniqueid');
	array_multisort($p1conids, SORT_NATURAL,
			$p1uniqueids, SORT_NUMERIC,
			$status);

	$p1connected = array();
	$p2connected = array();
	if (!is_array($status)) {
		$status = array();
	}

	foreach ($status as $ikesa) {
		list($ikeid, $reqid) = ipsec_id_by_conid($ikesa['con-id']);
		if (!array_key_exists($ikeid, $cmap)) {
			// Doesn't match known tunnel
			$p1connected[$ikesa['con-id']] = $ikesa['con-id'];
		} else {
			$p1connected[$ikeid] = $ph1idx = $ikeid;
		}
        
		if (array_key_exists('child-sas', $ikesa) && is_array($ikesa['child-sas'])) {
			$p2conids = array_column($ikesa['child-sas'], 'name');
			$p2uniqueids = array_column($ikesa['child-sas'], 'uniqueid');
			array_multisort($p2conids, SORT_NATURAL,
					$p2uniqueids, SORT_NUMERIC,
					$ikesa['child-sas']);

			foreach ($ikesa['child-sas'] as $childsa) {
				list($childikeid, $childreqid) = ipsec_id_by_conid($childsa['name']);
				if ($childreqid != null) {
					$p2connected[$childreqid] = $childsa['name'];
				} else {
					/* If this is IKEv2 w/o Split, mark all reqids for the P1 as connected */
					if (($cmap[$childikeid]['p1']['iketype'] == 'ikev2') &&
					    !isset($cmap[$childikeid]['p1']['splitconn']) &&
					    isset($cmap[$ikeid]['p2']) && is_array($cmap[$ikeid]['p2'])) {
						foreach ($cmap[$ikeid]['p2'] as $p2) {
							$p2connected[$p2['reqid']] = $childsa['name'];
						}
					}
				}
			}
		}
		$p2disconnected = array();
		if (!$cmap[$ikeid]['p1']['mobile'] &&
		    isset($cmap[$ikeid]) &&
		    is_array($cmap[$ikeid]) &&
		    is_array($cmap[$ikeid]['p2'])) {
			foreach ($cmap[$ikeid]['p2'] as $p2) {
				if (!array_key_exists($p2['reqid'], $p2connected)) {
					/* This P2 is not connected */
					$p2conid = ipsec_conid($cmap[$ikeid]['p1'], $p2);
					$p2disconnected[$p2conid] = $p2;
				}
			}
		}

        $data_item = array();

		$data_item["con_id"] = $ikesa['con-id'];
		$data_item["unique_id"] = $ikesa['uniqueid'];
		$data_item["description"] = $cmap[$ikeid]['p1']['descr'];

		$local = array();
		$localid = gettext("Unknown");
		if (!empty($ikesa['local-id'])) {
			if ($ikesa['local-id'] == '%any') {
				$localid = gettext('Any identifier');
			} else {
				$localid = $ikesa['local-id'];
			}
		}
        $local["id"] = $localid;

		$lhost = gettext("Unknown");
		if (!empty($ikesa['local-host'])) {
			$lhost = $ikesa['local-host'];
			if (!empty($ikesa['local-port'])) {
				if (is_ipaddrv6($ikesa['local-host'])) {
					$lhost = "[{$lhost}]";
				}
				$lhost .= ":{$ikesa['local-port']}";
			}
		}
        $local["host"] = $lhost;
		$local["spi"] = ($ikesa['initiator'] == 'yes') ? $ikesa['initiator-spi'] : $ikesa['responder-spi'];
		
		if (isset($ikesa['nat-local'])):
			$local["nat"] = gettext("NAT-T");
		else:
			$local["nat"] = null;
		endif;

		$data_item["local"] = $local;

		$remote = array();

		$identity = "";
		if (!empty($ikesa['remote-id'])) {
			if ($ikesa['remote-id'] == '%any') {
				$identity = gettext('Any identifier');
			} else {
				$identity = $ikesa['remote-id'];
			}
		}
		
		$remoteid = "";
		if (!empty($ikesa['remote-xauth-id'])) {
			$remoteid = $ikesa['remote-xauth-id'];
		} elseif (!empty($ikesa['remote-eap-id'])) {
			$remoteid = $ikesa['remote-eap-id'];
		} else {
			if (empty($identity)) {
				$identity = gettext("Unknown");
			}
		}

		$remote["id"] = $identity;

		if (!empty($remoteid)):
		    $remote["id"] .= " {$remoteid}";
		endif;

		$rhost = gettext("Unknown");
		if (!empty($ikesa['remote-host'])) {
			$rhost = $ikesa['remote-host'];
			if (!empty($ikesa['remote-port'])) {
				if (is_ipaddrv6($ikesa['remote-host'])) {
					$rhost = "[{$rhost}]";
				}
				$rhost .= ":{$ikesa['remote-port']}";
			}
		}
		$remote["host"] = $rhost;

		$remote["spi"] = ($ikesa['initiator'] == 'yes') ? $ikesa['responder-spi'] : $ikesa['initiator-spi'];

		if (isset($ikesa['nat-remote'])):
		    $remote["nat"] = gettext("NAT-T");
		else:
			$remote["nat"] = null;
		endif;

		$data_item["remote"] = $remote;

		$role = array();
		$role["ike_version"] = "IKEv{$ikesa['version']}";
		
		if ($ikesa['initiator'] == 'yes'):
		    $role["type"] = gettext("Initiator");
		else:
    		$role["type"] = gettext("Responder");
		endif;
		
		$data_item["role"] = $role;

		$timers = array();
		if ($ikesa['version'] == 2):
			if (!empty($ikesa['rekey-time'])):
		        $timers["rekey"] = $ikesa['rekey-time'];
			else:
		        $timers["rekey"] = null;
			endif;
		else:
			$timers["rekey"] = null;
		endif;
		if (!empty($ikesa['reauth-time'])):
		    $timers["reauth"] = $ikesa['reauth-time'];
		else:
		    $timers["reauth"] = null;
		endif;

		$data_item["timers"] = $timers;

		$algorithm = array();
		$algorithm["encr-alg"] = $ikesa['encr-alg'];
		if (!empty($ikesa['encr-keysize'])):
		    $algorithm["encr-keysize"] = $ikesa['encr-keysize'];
		else:
			$algorithm["encr-keysize"] = null;
		endif;

		$algorithm["integ-alg"] = $ikesa['integ-alg'];
		$algorithm["prf-alg"] = $ikesa['prf-alg'];
		$algorithm["dh-group"] = $ikesa['dh-group'];

		$data_item["algorithm"] = $algorithm;

		$state = array();
		$state["state"] = $ikesa['state'];

		if ($ikesa['state'] == 'ESTABLISHED'):
		    $state["established"] = $ikesa['established'];
        else:
            $state["established"] = null;
		endif;

        $state["p2_total"] = count($ikesa['child-sas']) + count($p2disconnected);
        $state["p2_connected"] = count($ikesa['child-sas']);

        $data_item["state"] = $state;

        $p2 = array();
		if (is_array($ikesa['child-sas']) && (count($ikesa['child-sas']) > 0)) {
			foreach ($ikesa['child-sas'] as $childsa) {
                $p2_item = array();
				list($childikeid, $childreqid) = ipsec_id_by_conid($childsa['name']);

                $p2_item["name"] = $childsa['name'];
                $p2_item["uniqueid"] = $childsa['uniqueid'];
                
				$p2descr = "";
				$p2uid = "";
				if (!empty($childreqid)) {
					/* IKEv1 or IKEv2+Split */
					$p2descr = $cmap[$childikeid]['p2'][$childreqid]['descr'];
					$p2uid = $cmap[$childikeid]['p2'][$childreqid]['uniqid'];
				} else {
					$childreqid = array_key_first(array_get_path($cmap, "{$childikeid}/p2", []));
					$p2uid = array_get_path($cmap, "{$childikeid}/p2/{$childreqid}/uniqid");
					if (count(array_get_path($cmap, "{$childikeid}/p2", [])) > 1) {
						$p2descr = gettext("Multiple");
					} else {
						$p2descr = array_get_path($cmap, "{$childikeid}/p2/{$childreqid}/descr");
					}
				}

			    $p2_item["description"] =  $p2descr;

				$lnetlist = array();
				if (is_array($childsa['local-ts'])) {
					foreach ($childsa['local-ts'] as $lnets) {
						$lnetlist[] = ipsec_fixup_network($lnets);
					}
				} else {
					$lnetlist[] = gettext("Unknown");
				}
			    $p2_item["local"] = $lnetlist;

				if (isset($childsa['spi-in'])) {
                    $p2_item["spi_local"] = $childsa['spi-in'];
                } else {
                    $p2_item["spi_local"] = null;
				}

				if (isset($childsa['spi-out'])) {
                    $p2_item["spi_remote"] = $childsa['spi-out'];
				} else {
                    $p2_item["spi_local"] = null;
				}

				$rnetlist = array();
				if (is_array($childsa['remote-ts'])) {
					foreach ($childsa['remote-ts'] as $rnets) {
						$rnetlist[] = ipsec_fixup_network($rnets);
					}
				} else {
					$rnetlist[] = gettext("Unknown");
				}
                $p2_item["remote"] = $rnetlist;

                $timers = array();
                
                $timers["rekey"] = $childsa['rekey-time'];
                $timers["life"] = $childsa['life-time'];
                $timers["install"] = $childsa['install-time'];

                $p2_item["timers"] = $timers;

                $algorithm = array();

			    $algorithm["encr-alg"] = $childsa['encr-alg'];

				if (!empty($childsa['encr-keysize'])):
			        $algorithm["encr-keysize"] = $childsa['encr-keysize'];
                else:
                    $algorithm["encr-keysize"] = null;
				endif;

			    $algorithm["integ-alg"] = $childsa['integ-alg'];

				if (!empty($childsa['prf-alg'])):
			        $algorithm["prf-alg"] = $childsa['prf-alg'];
                else:
                    $algorithm["prf-alg"] = null;
				endif;

				if (!empty($childsa['dh-group'])):
			        $algorithm["dh-group"] = $childsa['dh-group'];
                else:
                    $algorithm["dh-group"] = null;
				endif;

				if (!empty($childsa['esn'])):
			        $algorithm["esn"] = $childsa['esn'];
                else:
                    $algorithm["esn"] = null;
				endif;

				$ipcomp = gettext('None');
				if (!empty($childsa['cpi-in']) || !empty($childsa['cpi-out'])) {
					$ipcomp = "{$childsa['cpi-in']} {$childsa['cpi-out']}";
				}

			    $algorithm["ipcomp"] = $ipcomp;

                $p2_item["algorithm"] = $algorithm;

                $stats = array();
                $stats["bytes_in"] = $childsa['bytes-in'];
                $stats["packets_in"] = $childsa['packets-in'];
                $stats["bytes_out"] = $childsa['bytes-out'];
                $stats["packets_out"] = $childsa['packets-out'];

                $p2_item["stats"] = $stats;

                $p2_item["state"] = $childsa['state'];

                $p2[] = $p2_item;
            }
		}
        foreach ($p2disconnected as $p2conid => $phase2) {
            $p2_item = array();
            $p2_item["name"] = $p2conid;
            $p2_item["description"] = $phase2['descr'];
            $p2_item["local"] = ipsec_idinfo_to_cidr($phase2['localid'], false, $phase2['mode']);
            $p2_item["remote"] = ipsec_idinfo_to_cidr($phase2['remoteid'], false, $phase2['mode']);

            $p2_item["state"] = "disconnected";
            $p2[] = $p2_item;
        }
        $data_item["p2"] = $p2;

        $data[] = $data_item;
	}

	$rgmap = array();
	$gateways_status = return_gateways_status(true);

	foreach ($cmap as $p1) {
		if (!array_key_exists('p1', $p1) ||
		    isset($p1['p1']['disabled'])) {
			continue;
		}
		$ph1ent = &$p1['p1'];
		$rgmap[$ph1ent['remote-gateway']] = $ph1ent['remote-gateway'];
		if ($p1connected[$ph1ent['ikeid']]) {
			continue;
		}
        $data_item = array();

        $data_item["con_id"] = ipsec_conid($ph1ent);
        $data_item["description"] = $ph1ent['descr'];

        $local = array();

		list ($myid_type, $myid_data) = ipsec_find_id($ph1ent, "local", array(), $gateways_status);
		if (empty($myid_data)) {
			$myid_data = gettext("Unknown");
		}
        $local["id"] = $myid_data;

		$ph1src = ipsec_get_phase1_src($ph1ent, $gateways_status);
		if (empty($ph1src)) {
			$ph1src = gettext("Unknown");
		} else {
			$ph1src = str_replace(',', ', ', $ph1src);
		}
        $local["host"] = $ph1src;

        $data_item["local"] = $local;

		if (!isset($ph1ent['mobile'])):
            $remote = array();
		    list ($peerid_type, $peerid_data) = ipsec_find_id($ph1ent, "peer", $rgmap, $gateways_status);
            if (empty($peerid_data)) {
                $peerid_data = gettext("Unknown");
            }
            $remote["id"] = $peerid_data;

            $ph1dst = ipsec_get_phase1_dst($ph1ent);
            if (empty($ph1dst)) {
                $ph1dst = print(gettext("Unknown"));
            }

		    $remote["host"] = $ph1dst;

            $data_item["remote"] = $remote;
		endif;

		if (isset($ph1ent['mobile'])):
		    $data_item["state"]["state"] = "awaiting_connections";
		else:
            $data_item["state"]["state"] = "disconnected";
		endif;
        $data[] = $data_item;
	}
	unset($p1connected, $p2connected, $p2disconnected, $rgmap);

    return $data;
}

function is_user_disabled($username) {
    $users = index_users();
    $user = $users[$username];
    if (config_path_enabled("system/user/{$user}", "disabled")) {
        return true;
    }
    return false;
}

function authenticate_local_database() {
    $username = $_SERVER['PHP_AUTH_USER'];
    $client_token = $_SERVER['PHP_AUTH_PW'];
    if (authenticate_user($username, $client_token)) {
        if (is_user_disabled($username) === false) {
            unset($_SESSION["Username"]);
            $_SESSION["Username"] = $username;
            return true;
        }
    }
    return false;
}

header('Content-Type: application/json');

if (!authenticate_local_database()) {
    http_response_code(401);
    die(json_encode([ "error" => "Unauthorized" ]));
}

$ipsec_status = get_ipsec_status();
if (!array_key_exists('error', $ipsec_status)) {
    http_response_code(200);
    echo json_encode($ipsec_status);
} else {
    http_response_code($ipsec_status["status_code"]);
    echo json_encode($ipsec_status["error"]);
}
