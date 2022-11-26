import requests, re, time
from bs4 import BeautifulSoup
import sqlite3
bdy = 'db.sqlite3'
con = sqlite3.connect(bdy)
cur = con.cursor()

def get_html(url):
    try:
        r = requests.get(url).text
        return r
    except requests.exceptions.ConnectionError:
        print('повтор', time.strftime("%Y-%m-%d-%H.%M.%S", time.localtime()))
        time.sleep(10)
        get_html(url)

def create_table():
    cur.execute('CREATE TABLE IF NOT EXISTS home_cpe(CPE_name TEXT, CVE_name TEXT)')
    cur.execute('CREATE TABLE IF NOT EXISTS home_cve(CVE_name TEXT, Date1 TEXT, Description TEXT, CVSS_name TEXT, CVSS_description TEXT, CWE_name TEXT, Hyperlink TEXT)')
    cur.execute('CREATE TABLE IF NOT EXISTS home_cwe(CWE_name TEXT, CAPEC_name TEXT )')
    cur.execute('CREATE TABLE IF NOT EXISTS home_cwe_description(CWE_name TEXT, CWE_description TEXT, CWE_link TEXT)')
    cur.execute('CREATE TABLE IF NOT EXISTS home_capec_description(CAPEC_name TEXT, CAPEC_description TEXT, CAPEC_link TEXT,id_ATT_CK TEXT, ATT_CK_name TEXT, ATT_CK_link TEXT)')
    cur.execute('CREATE TABLE IF NOT EXISTS home_att_ck(id_att_ck TEXT, name_att_ck TEXT, description_att_ck TEXT,tactic TEXT, platform TEXT, permissions_required TEXT, effective_permissions TEXT, data_sources TEXT,defense_bypassed TEXT, version TEXT)')

def cpe_table_insert(cpe, cve):
    con = sqlite3.connect(bdy)
    cur = con.cursor()
    cur.execute("INSERT INTO home_cpe (CPE_name, CVE_name) VALUES (?,?)",(cpe, cve))
    con.commit()

def cwe_table_insert(cwe, capec):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    cur.execute("INSERT INTO home_cwe (CWE_name , CAPEC_name ) VALUES (?,?)",(cwe, capec))
    conn.commit()

def cve_insert_data(data_cve):
    cve_name = data_cve[0]
    date = data_cve[1]
    Description = data_cve[2]
    vector = data_cve[3]
    svss_description = data_cve[4]
    name_cwe_total = data_cve[5]
    links_solutions_str = data_cve[6]
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    cur.execute("INSERT INTO home_cve (CVE_name, Date1, Description, CVSS_name, CVSS_description, CWE_name, Hyperlink) VALUES (?,?,?,?,?,?,?)",(cve_name, date, Description, vector, svss_description, name_cwe_total, links_solutions_str))
    conn.commit()

def update_cve(data_cve):
    cve_name = data_cve[0]
    date = data_cve[1]
    Description = data_cve[2]
    vector = data_cve[3]
    svss_description = data_cve[4]
    name_cwe_total = data_cve[5]
    links_solutions_str = data_cve[6]
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    cur.execute("UPDATE home_cve SET CVE_name=?, Date1=?, Description=?, CVSS_name=?, CVSS_description=?, CWE_name=?, Hyperlink=? where CVE_name=?",(cve_name, date, Description, vector, svss_description, name_cwe_total, links_solutions_str, cve_name))
    conn.commit()

def cwe_update_data(cwe_n, cwe_d, cwe_l):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    cur.execute("UPDATE home_cwe_description SET CWE_name=? , CWE_description=? , CWE_link=? WHERE  CWE_name=?", (cwe_n, cwe_d, cwe_l, cwe_n))
    conn.commit()

def cwe_insert_data(cwe_n, cwe_d, cwe_l):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    cur.execute("INSERT INTO home_cwe_description (CWE_name , CWE_description , CWE_link ) VALUES (?,?,?)",(cwe_n, cwe_d, cwe_l))
    conn.commit()

def capec_insert_data(capec_n, capec_d, capec_l, id_ATT_CK, ATT_CK_name, ATT_CK_link):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    cur.execute("INSERT INTO home_capec_description (CAPEC_name , CAPEC_description , CAPEC_link, id_ATT_CK, ATT_CK_name, ATT_CK_link) VALUES (?,?,?,?,?,?)",(capec_n, capec_d, capec_l, id_ATT_CK, ATT_CK_name, ATT_CK_link))
    conn.commit()

def capec_update_data(capec_n, capec_d, capec_l, id_ATT_CK, ATT_CK_name, ATT_CK_link):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    cur.execute("UPDATE home_capec_description SET CAPEC_name=? , CAPEC_description=? , CAPEC_link=?, id_ATT_CK=?, ATT_CK_name=?, ATT_CK_link=? WHERE CAPEC_name=?",(capec_n, capec_d, capec_l, id_ATT_CK, ATT_CK_name, ATT_CK_link, capec_n))
    conn.commit()

def att_ck_insert_data(id_att_ck, name_att_ck, description_att_ck, tactic, platform, permissions_required, effective_permissions, data_sources,defense_bypassed, version):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    cur.execute("INSERT INTO home_att_ck (id_att_ck , name_att_ck , description_att_ck, tactic, platform, permissions_required, effective_permissions, data_sources,defense_bypassed, version) VALUES (?,?,?,?,?,?,?,?,?,?)",(id_att_ck, name_att_ck, description_att_ck, tactic, platform, permissions_required, effective_permissions, data_sources,defense_bypassed, version))
    conn.commit()

def att_ck_update_data(id_att_ck, name_att_ck, description_att_ck, tactic, platform, permissions_required, effective_permissions, data_sources,defense_bypassed, version):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    cur.execute("UPDATE home_att_ck SET id_att_ck=? , name_att_ck=? , description_att_ck=?, tactic=?, platform=?, permissions_required=?, effective_permissions=?, data_sources=?,defense_bypassed=?, version=? WHERE id_att_ck=?",(id_att_ck, name_att_ck, description_att_ck, tactic, platform, permissions_required, effective_permissions,data_sources, defense_bypassed, version, id_att_ck))
    conn.commit()

def comparison_cve(cve_name):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    query = "SELECT * FROM home_cve WHERE CVE_name == " +'\"'+str(cve_name) + '\"' + ";"
    #query1  = "SELECT * FROM cve WHERE CVE_name == " +'\"'+str('CVE-2019-666') + '\"' + ";"
    cur.execute(query)
    data_res = cur.fetchall()
    return data_res

def comparison_cwe(name_cwe):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    query = "SELECT * FROM home_cwe WHERE CWE_name == " + '\"' + name_cwe + '\"' + ";"
    query1 = "SELECT * FROM home_cwe WHERE CWE_name == " + '\"' + str('CWE-6572134') + '\"' + ";"
    cur.execute(query)
    cwe_res = cur.fetchall()
    return cwe_res

def comparison_capec(name_capec):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    query = "SELECT * FROM home_capec_description WHERE CAPEC_name == " + '\"' + name_capec + '\"' + ";"
    query1 = "SELECT * FROM home_capec_description WHERE CAPEC_name == " + '\"' + str('CWE-6572134') + '\"' + ";"
    cur.execute(query)
    capec_res = cur.fetchall()
    return capec_res

def comparison_att_ck(id_att_ck):
    conn = sqlite3.connect(bdy)
    cur = conn.cursor()
    query = "SELECT * FROM home_att_ck WHERE id_att_ck == " + '\"' + id_att_ck + '\"' + ";"
    #query1 = "SELECT * FROM home_capec_description WHERE CAPEC_name == " + '\"' + str('CWE-6572134') + '\"' + ";"
    cur.execute(query)
    att_ck_res = cur.fetchall()
    return att_ck_res

def full_listing(html):
    months_links = []
    soup = BeautifulSoup(html, 'lxml')
    years = soup.findAll('ul', class_='list-inline')
    for i in years:
        months = i.findAll('a')
        for i in months:
            months_links.append('https://nvd.nist.gov/' + i.get('href'))
    return months_links

def month(link):
    cve_s_links = []
    html = get_html(link)
    soup = BeautifulSoup(html, 'lxml')
    span_s = soup.findAll('span', class_='col-md-2')
    for span in span_s:
        cve_s_links.append('https://nvd.nist.gov' + span.find('a').get('href'))
    #print(cve_s_links, '\n', len(cve_s_links))
    return cve_s_links

def get_name_all_cpe(link):
    html = get_html(link)
    cpe_name = []
    cpe_s = ''.join(re.findall(r'<input type="hidden".*/>', str(html))).split(';')

    for i in cpe_s:
        if (i[0:8] == 'cpe:2.3:'):
            cpe_name.append(i[0:-5])


    return cpe_name

def get_data_cve(link_cve):
    #link_cve = 'https://nvd.nist.gov/vuln/detail/CVE-2021-3005'
    links_cwe=[]
    cve_name_link = link_cve.split('/')[5]
    print(cve_name_link)
    data_res = comparison_cve(cve_name_link)
    #print('data_res ', data_res)
    if (len(data_res) == 0):
        html = get_html(link_cve)
        if (html == None):
            html = get_html(link_cve)
        soup = BeautifulSoup(html, 'lxml')

        div = soup.find('div', class_='col-lg-9 col-md-7 col-sm-12')
        date = str('Date: ' + soup.find('span', {'data-testid': 'vuln-published-on'}).next)
        cve_name = soup.find('span', {'data-testid':'page-header-vuln-id'}).text
        print(cve_name)
        des = div.find('p', {'data-testid': 'vuln-description'}).text
        #print(des)

        try:
            base_score = div.find('a',id='Cvss2CalculatorAnchor').text
            print(base_score)
            des_full = '\n'.join([base_score, des])
            vector = div.find('span', {'data-testid': 'vuln-cvss2-panel-vector'}).text
            # vector = 'N/A'
            table_links = div.find('table', class_='table table-striped table-condensed table-bordered detail-table').find_all('a')
            links_solutions = []
            for a in table_links:
                link_solution = 'Ссылка на решение: ' + a.get('href')
                links_solutions.append(link_solution)
            links_solutions_str = '\n'.join(links_solutions)
            table_cwe = soup.find('table', {'data-testid': 'vuln-CWEs-table'})

            cwe_id = table_cwe.find('td', {'data-testid': 'vuln-CWEs-link-0'}).text.strip()

            cwe_name = table_cwe.find_all('td', {'data-testid': 'vuln-CWEs-link-0'})[-1].text + " "
            print(cwe_name)

            full_name_cwe = cwe_name + '(' + cwe_id + ')'
            try:
                link_cwe = table_cwe.find('td', {'data-testid': 'vuln-CWEs-link-0'}).find('a').get('href')
                links_cwe.append(link_cwe)
            except: links_cwe = []
            #if (len(link_cwe)!=0):
            svss_description = 'NONE'
            data_cve = [cve_name, date, des_full, vector, svss_description, full_name_cwe, links_solutions_str]
            cve_insert_data(data_cve)
            #div_cpe_s = soup.find('div',id='p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_VulnConfigurationsDiv')
            link_cpe_all = 'https://nvd.nist.gov/vuln/detail/' + cve_name + '/cpes?expandCpeRanges=true'
            print(link_cpe_all)
            cpe_name = get_name_all_cpe(link_cpe_all)
            if (len(cpe_name)==0): cpe_name.append('NONE')
            for cpe in cpe_name:
                cpe_table_insert(cpe, cve_name)
            print(links_cwe)
            if (len(links_cwe)!=0): links_cwe = list(set(links_cwe))
            return links_cwe
        except:
            base_score = 'NONE'
            vector = 'NONE'
            full_name_cwe = 'NONE'
            des_full = '\n'.join([base_score, des])
            svss_description = 'NONE'
            links_solutions_str = 'NONE'
            data_cve = [cve_name, date, des_full, vector, svss_description, full_name_cwe, links_solutions_str]
            cve_insert_data(data_cve)
            cpe_table_insert('NONE', cve_name)
    else:
        html = get_html(link_cve)
        if (html == None):
            html = get_html(link_cve)
        #print(html)
        soup = BeautifulSoup(html, 'lxml')

        div = soup.find('div', class_='col-lg-9 col-md-7 col-sm-12')
        date = str('Date: ' + soup.find('span', {'data-testid': 'vuln-published-on'}).next)
        cve_name = soup.find('span', {'data-testid': 'page-header-vuln-id'}).text
        print(cve_name)
        des = div.find('p', {'data-testid': 'vuln-description'}).text
        try:
            base_score = div.find('a', id='Cvss2CalculatorAnchor').text
            print(base_score)
            des_full = '\n'.join([base_score, des])
            vector = div.find('span', {'data-testid': 'vuln-cvss2-panel-vector'}).text
            # vector = 'N/A'
            table_links = div.find('table',class_='table table-striped table-condensed table-bordered detail-table').find_all('a')
            links_solutions = []
            for a in table_links:
                link_solution = 'Ссылка на решение: ' + a.get('href')
                links_solutions.append(link_solution)
            links_solutions_str = '\n'.join(links_solutions)
            table_cwe = soup.find('table', {'data-testid': 'vuln-CWEs-table'})

            cwe_id = table_cwe.find('td', {'data-testid': 'vuln-CWEs-link-0'}).text.strip()

            cwe_name = table_cwe.find_all('td', {'data-testid': 'vuln-CWEs-link-0'})[-1].text + " "
            print(cwe_name)

            full_name_cwe = cwe_name + '(' + cwe_id + ')'
            try:
                link_cwe = table_cwe.find('td', {'data-testid': 'vuln-CWEs-link-0'}).find('a').get('href')
                links_cwe.append(link_cwe)
            except: links_cwe = []

            svss_description = 'NONE'
            data_cve = [cve_name, date, des_full, vector, svss_description, full_name_cwe, links_solutions_str]
            update_cve(data_cve)
            if (len(links_cwe) != 0): links_cwe = list(set(links_cwe))
            return links_cwe

        except:
            base_score = 'NONE'
            vector = 'NONE'
            full_name_cwe = 'NONE'
            des_full = '\n'.join([base_score, des])
            svss_description = 'NONE'
            links_solutions_str = 'NONE'
            data_cve = [cve_name, date, des_full, vector, svss_description, full_name_cwe, links_solutions_str]
            update_cve(data_cve)
            #update_cpe('NONE', cve_name)

def get_data_cwe(Links_cwe):
    links_capec = []
    names_capec = []
    for link_cwe in Links_cwe:
        name_cwe = 'CWE-'+str(link_cwe).split("/")[5].split('.')[0]
        if (name_cwe=='CWE-CWE-noinfo' or name_cwe=='CWE-CWE-Other'): name_cwe = '-'.join(name_cwe.split('-')[1:])
        cwe_res=comparison_cwe(name_cwe)
        if(len(cwe_res)==0):
            html = get_html(link_cwe)
            if (html == None):
                html = get_html(link_cwe)
            soup = BeautifulSoup(html, 'lxml')
            div = soup.find('div',  id='Related_Attack_Patterns')
            if (str(div)=='None'):
                cwe_table_insert(name_cwe,'NONE')
                div_discr = soup.find('div', id='Description')
                if (str(div_discr)=='None'):
                    div_sum = soup.find('div', id='Summary')
                    if(str(div_sum)=='None'):
                        cwe_insert_data(name_cwe,'NULL',link_cwe)
                        continue
                    div_indent_sum = div_sum.find('div', class_='indent').next
                    cwe_insert_data(name_cwe,div_indent_sum, link_cwe)
                    continue
                div_indent = div_discr.find('div', class_='indent').next
                cwe_insert_data(name_cwe, div_indent, link_cwe)
                continue
            a_all=div.find_all('a', target='_blank', rel='noopener noreferrer')
            for a in a_all:
                name_capec=a.next
                names_capec.append(name_capec)
                link_capec=a.get('href')
                links_capec.append(link_capec)
                cwe_table_insert(name_cwe, name_capec)
            div_discr = soup.find('div', id='Description')
            if (str(div_discr) == 'None'):
                div_sum = soup.find('div', id='Summary')
                if (str(div_sum) == 'None'):
                    cwe_insert_data(name_cwe, 'NULL', link_cwe)
                    continue
                div_indent_sum = div_sum.find('div', class_='indent').next
                cwe_insert_data(name_cwe, div_indent_sum, link_cwe)
            div_indent = div_discr.find('div', class_='indent').next

            cwe_insert_data(name_cwe, div_indent, link_cwe)
        else:
            html = get_html(link_cwe)
            if (html == None):
                html = get_html(link_cwe)
            soup = BeautifulSoup(html, 'lxml')
            div = soup.find('div', id='Related_Attack_Patterns')
            if (str(div) == 'None'):
                #cwe_table_insert(name_cwe, 'NONE')
                div_discr = soup.find('div', id='Description')
                if (str(div_discr) == 'None'):
                    div_sum = soup.find('div', id='Summary')
                    if (str(div_sum) == 'None'):
                        cwe_insert_data(name_cwe, 'NULL', link_cwe)
                        continue
                    div_indent_sum = div_sum.find('div', class_='indent').next
                    cwe_insert_data(name_cwe, div_indent_sum, link_cwe)
                    continue
                div_indent = div_discr.find('div', class_='indent').next
                cwe_insert_data(name_cwe, div_indent, link_cwe)
                continue
            a_all = div.find_all('a', target='_blank', rel='noopener noreferrer')
            for a in a_all:
                name_capec = a.next
                names_capec.append(name_capec)
                link_capec = a.get('href')
                links_capec.append(link_capec)
                #cwe_table_insert(name_cwe, name_capec)
            div_discr = soup.find('div', id='Description')
            if (str(div_discr) == 'None'):
                div_sum = soup.find('div', id='Summary')
                if (str(div_sum) == 'None'):
                    cwe_insert_data(name_cwe, 'NULL', link_cwe)
                    continue
                div_indent_sum = div_sum.find('div', class_='indent').next
                cwe_insert_data(name_cwe, div_indent_sum, link_cwe)
            div_indent = div_discr.find('div', class_='indent').next

            cwe_update_data(name_cwe, div_indent, link_cwe)

    links_capec=list(set(links_capec))
    return links_capec

def get_data_capec(links_capec):
    links_attack_all = []
    links_attack = []
    for link_capec in links_capec:
        #link_capec = "https://capec.mitre.org/data/definitions/16.html"
        ids_ATT_CK = []
        names_ATT_CK = []

        name_capec = 'CAPEC-' + str(link_capec).split('/')[5].split('.')[0]
        res_capec = comparison_capec(name_capec)
        if (len(res_capec)==0):
            html = get_html(link_capec)
            if (html == None):
                html = get_html(link_capec)
            soup = BeautifulSoup(html, 'lxml')
            div = soup.find('div', id = 'Description')
            capec_discr = re.sub(r'<[/]*p>', '', str(div.find('div', class_='indent').next))
            #print(name_capec, '\n', capec_discr, '\n', links_capec)
            try:
                div_attack = [] #= soup.find('div', class_='tax_title').parent.find_all('a')
                if (soup.find('div', class_='tax_title').text == "Relevant to the ATT&CK taxonomy mapping"):
                    div_attack_temp = soup.find('div', class_='tax_title').parent.find_all('a')
                    for a in div_attack_temp:
                        if (re.search(r'https://attack.mitre.org/wiki/Technique/', str(a)) == None): continue
                        div_attack.append(a)
                    print(link_capec)
                else:
                    ids_ATT_CK.append('NONE')
                    names_ATT_CK.append('NONE')
                    capec_insert_data(name_capec, capec_discr, link_capec, str(ids_ATT_CK)[2:-2], str(names_ATT_CK)[2:-2], 'NONE')
                    continue
                #print(div_attack)
            except:
                ids_ATT_CK.append('NONE')
                names_ATT_CK.append('NONE')
                capec_insert_data(name_capec, capec_discr, link_capec, str(ids_ATT_CK)[2:-2], str(names_ATT_CK)[2:-2], 'NONE')
                continue
            for a in div_attack:
                link_attack = a.get('href')

                links_attack.append(str(link_attack))
                id = a.text
                ids_ATT_CK.append(str(id))
                name_ATT_CK = a.next.next.text
                names_ATT_CK.append(str(name_ATT_CK))
            for id, name, link in zip(ids_ATT_CK, names_ATT_CK, links_attack):
                capec_insert_data(str(name_capec), str(capec_discr), str(link_capec), str('T'+id), str(name), str(link))
            print(links_attack)
            for i in links_attack:
                links_attack_all.append(i)
            links_attack.clear()
        else:
            html = get_html(link_capec)
            if (html == None):
                html = get_html(link_capec)
            soup = BeautifulSoup(html, 'lxml')
            div = soup.find('div', id='Description')
            capec_discr = re.sub(r'<[/]*p>', '', str(div.find('div', class_='indent').next))
            # print(name_capec, '\n', capec_discr, '\n', links_capec)
            try:
                div_attack = []  # = soup.find('div', class_='tax_title').parent.find_all('a')
                if (soup.find('div', class_='tax_title').text == "Relevant to the ATT&CK taxonomy mapping"):
                    div_attack_temp = soup.find('div', class_='tax_title').parent.find_all('a')
                    for a in div_attack_temp:
                        if (re.search(r'https://attack.mitre.org/wiki/Technique/', str(a)) == None): continue
                        div_attack.append(a)
                    print(link_capec)
                else:
                    ids_ATT_CK.append('NONE')
                    names_ATT_CK.append('NONE')
                    capec_update_data(name_capec, capec_discr, link_capec, str(ids_ATT_CK)[2:-2], str(names_ATT_CK)[2:-2], 'NONE')
                    continue
                # print(div_attack)
            except:
                ids_ATT_CK.append('NONE')
                names_ATT_CK.append('NONE')
                capec_update_data(name_capec, capec_discr, link_capec, str(ids_ATT_CK)[2:-2], str(names_ATT_CK)[2:-2], 'NONE')
                continue
            for a in div_attack:
                link_attack = a.get('href')

                links_attack.append(str(link_attack))
                id = a.text
                ids_ATT_CK.append(str(id))
                name_ATT_CK = a.next.next.text
                names_ATT_CK.append(str(name_ATT_CK))
            for id, name, link in zip(ids_ATT_CK, names_ATT_CK, links_attack):
                capec_update_data(str(name_capec), str(capec_discr), str(link_capec), str('T' + id), str(name), str(link))
            print(links_attack)
            for i in links_attack:
                links_attack_all.append(i)
            links_attack.clear()
    print('links', links_attack_all)
    links_attack_all = list(set(links_attack_all))
    return links_attack_all

def get_data_ATT_CK(links_ATT_CK):
    for link in links_ATT_CK:
        #link = "https://attack.mitre.org/techniques/T1550/004"
        link = re.sub(r'Technique', 'techniques', link)
        link = re.sub(r'wiki/', '', link)
        link_html = get_html(link)
        if (link_html == None):
            link_html = get_html(link)
        soup = BeautifulSoup(link_html, 'lxml')
        div = soup.find('div', class_='jumbotron jumbotron-fluid')
        id = link.split('techniques')[-1][1:].replace('/','.')
        res_add_ck = comparison_att_ck(id)
        if (len(res_add_ck) == 0):
            name_ATT_CK = re.sub(r' {5,}', '', str(div.find('h1').text).strip())
            dis_ATT_CK_tag_p = div.find('div', class_='description-body').find_all('p')
            dis_ATT_CK = ''
            for p in dis_ATT_CK_tag_p:
                dis_ATT_CK = dis_ATT_CK + str(p.text).strip() + '\n'
            spans_card = div.find('div', class_='col-md-4').find_all('span', class_='h5 card-title')
            tactic = ''
            platform = ''
            permissions_required = ''
            effective_permissions = ''
            data_sources = ''
            version = ''
            defense_bypassed = ''
            for span in spans_card:
                span_str = str(span.text).strip()
                if (span_str=='Tactic:' or span_str=='Tactics:'):
                    tactic = str(span.parent.text).strip()
                    tactic = re.sub(r',', ', ', re.sub(r'\n', ' ', re.sub(r' {20,}', '', tactic)))
                    continue
                elif (span_str=='Platforms:'):
                    platform = str(span.parent.text).strip()
                    continue
                elif (span_str=='Permissions Required:'):
                    permissions_required = str(span.parent.text).strip()
                    continue
                elif ( span_str=='Effective Permissions:'):
                    effective_permissions = str(span.parent.text).strip()
                    continue
                elif (span_str=='Data Sources:'):
                    data_sources = str(span.parent.text).strip()
                    continue
                elif (span_str=='Version:'):
                    version = str(span.parent.text).strip()
                elif (span_str=='Defense Bypassed:'):
                    defense_bypassed = str(span.parent.text).strip()
                    continue
            att_ck_insert_data(id, name_ATT_CK, dis_ATT_CK, tactic, platform, permissions_required, effective_permissions, data_sources,defense_bypassed, version)
        else:
            name_ATT_CK = re.sub(r' {5,}', '', str(div.find('h1').text).strip())
            dis_ATT_CK_tag_p = div.find('div', class_='description-body').find_all('p')
            dis_ATT_CK = ''
            for p in dis_ATT_CK_tag_p:
                dis_ATT_CK = dis_ATT_CK + str(p.text).strip() + '\n'
            spans_card = div.find('div', class_='col-md-4').find_all('span', class_='h5 card-title')
            tactic = ''
            platform = ''
            permissions_required = ''
            effective_permissions = ''
            data_sources = ''
            version = ''
            defense_bypassed = ''
            for span in spans_card:
                span_str = str(span.text).strip()
                if (span_str == 'Tactic:' or span_str == 'Tactics:'):
                    tactic = str(span.parent.text).strip()
                    tactic = re.sub(r',', ', ', re.sub(r'\n', ' ', re.sub(r' {20,}', '', tactic)))
                    continue
                elif (span_str == 'Platforms:'):
                    platform = str(span.parent.text).strip()
                    continue
                elif (span_str == 'Permissions Required:'):
                    permissions_required = str(span.parent.text).strip()
                    continue
                elif (span_str == 'Effective Permissions:'):
                    effective_permissions = str(span.parent.text).strip()
                    continue
                elif (span_str == 'Data Sources:'):
                    data_sources = str(span.parent.text).strip()
                    continue
                elif (span_str == 'Version:'):
                    version = str(span.parent.text).strip()
                elif (span_str == 'Defense Bypassed:'):
                    defense_bypassed = str(span.parent.text).strip()
                    continue
            att_ck_update_data(id, name_ATT_CK, dis_ATT_CK, tactic, platform, permissions_required, effective_permissions, data_sources, defense_bypassed, version)

def main():
    create_table()
    url = 'https://nvd.nist.gov/vuln/full-listing'
    months_links = full_listing(get_html(url))
    print(months_links)
    n = 660#955
    x = 660
    a=0
    a1=12#3
    for i in range(a1, len(months_links)):
        #a1 = a1 + 2
        print(a1, ' ', months_links[i])
        cve_s_links = month(months_links[i])
        # f = open('point.txt', 'a')
        # f.write('month: ' + str(a) +'\n')
        # f.close()

        for i in range(n, len(cve_s_links)):
            a = a + x
            print(a, ' ', cve_s_links[i])
            Links_cwe = get_data_cve(cve_s_links[i])
            print(Links_cwe)
            if (Links_cwe==None): continue
            links_capec = get_data_cwe(Links_cwe)
            links_ATT_CK = get_data_capec(links_capec)
            get_data_ATT_CK(links_ATT_CK)
            Links_cwe.clear()
            f = open('point.txt', 'a')
            f.write('month: '+ str(a1)+ '\n'+ 'cve: ' + str(a) + '\n')
            f.close()
            x = 0
            a = a + 1
        n=0
        a=0
        a1 = a1+1

if __name__ == '__main__':
    main()
