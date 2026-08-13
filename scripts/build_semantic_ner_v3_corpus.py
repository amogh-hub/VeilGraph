#!/usr/bin/env python3
from __future__ import annotations
import json, random
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'backend'/'training_data'/'semantic_ner_train_v3.json'
rng=random.Random(2603815)

first=['Aarav','Meera','Kabir','Nisha','Rohan','Tara','Leena','Dev','Ananya','Arjun','Isha','Vikram','Riya','Neel','Kavya','Sanjay','Maya','Aditi','Rahul','Priya','Daniel','Alice','Michael','Sofia','Elena','David','Maria','Thomas','Grace','Noah','Emma','Oliver','Amelia','Lucas','Chloe','Samuel','Hannah','Victor','Nora','Omar','Layla']
last=['Menon','Iyer','Shah','Kulkarni','Das','Singh','Thomas','Malhotra','Shetty','Bhat','Nair','Joshi','Rao','Patel','Gupta','Fernandes','Brown','Smith','Johnson','Miller','Wilson','Taylor','Anderson','Martin','Clark','Lewis','Walker','Hall','Young','King','Wright','Scott','Green','Baker','Adams','Nelson','Carter','Mitchell','Perez','Roberts']
org_heads=['Meridian','Northstar','Cedar','Nimbus','Orion','Sapphire','Central','Harbor','Summit','Pioneer','Civic','Riverstone','Evergreen','Atlas','Sterling','Oakbridge','Bluewater','Redwood','Silverline','Westfield']
org_tails=['Research Foundation','Health Trust','Analytics Pvt Ltd','Legal Services','Mobility Systems','University','Medical College','District Hospital','Technology Group','Community Bank','Public Authority','Research Institute','Support Services','Data Systems','Clinical Labs','Regional Council','Education Board','Insurance Company','Consulting Group']
places=['Bengaluru','Mysuru','Chennai','Pune','Jaipur','Ahmedabad','Gurugram','Hyderabad','Kochi','Thiruvananthapuram','London','Manchester','Bristol','Leeds','Birmingham','New Delhi','Mumbai','Kolkata','Lucknow','Indore','Toronto','Dublin','Sydney','Auckland','Nairobi','Cape Town','Singapore','Dubai','Colombo','Kathmandu']
roles=['Senior Analyst','Research Scientist','Software Engineer','Medical Officer','Project Manager','Legal Counsel','Data Protection Officer','Financial Auditor','Clinical Researcher','Operations Director','Security Architect','Case Worker','Compliance Manager','Staff Nurse','Consultant Physician','Investigation Officer','Policy Advisor','University Lecturer','Account Manager','Systems Administrator']
streets=['12 Park Street','44 Lake View Road','7 Cedar Avenue','310 River Lane','18 MG Road','92 Station Road','51 Oak Crescent','604 Hill Street','27 Garden Avenue','16 Residency Road','225 King Street','80 Market Lane','17 Church Road','9 Victoria Avenue','33 Queens Drive','104 Maple Street']

examples=[]
def add(et, pattern, text, value, accept):
    start=text.index(value); examples.append({'entity_type':et,'pattern':pattern,'text':text,'value':value,'start':start,'end':start+len(value),'accept':bool(accept)})

def name():
    if rng.random() < 0.42:
        return rng.choice(first)+' '+rng.choice(first)+' '+rng.choice(last)
    return rng.choice(first)+' '+rng.choice(last)
def org(): return rng.choice(org_heads)+' '+rng.choice(org_tails)

# PERSON positives across legal/report/prose contexts.
for _ in range(120):
    n=name(); h=rng.choice(['Mr','Ms','Mrs','Dr','Professor','Judge','Officer'])
    text=f'{h}. {n} stated that the record was inaccurate.'; add('PERSON_NAME','honorific-person',text,n,True)
for _ in range(120):
    n=name(); role=rng.choice(['applicant','claimant','complainant','respondent','witness','patient','employee','client','participant','guardian'])
    text=f'The {role}, {n}, submitted a written statement.'; add('PERSON_NAME','role-person',text,n,True)
for _ in range(90):
    n=name(); role=rng.choice(['applicant','respondent','witness','patient','employee'])
    text=f'{n}, the {role}, attended the review.'; add('PERSON_NAME','person-before-role',text,n,True)
for _ in range(100):
    n=name(); action=rng.choice(['met','contacted','interviewed','signed by','prepared by','submitted by','represented by','treated by','identified as'])
    text=f'The report was {action} {n} after the meeting.' if action in {'signed by','prepared by','submitted by','represented by','treated by'} else f'The officer {action} {n} after the meeting.'
    add('PERSON_NAME','action-person',text,n,True)
for _ in range(100):
    n=name(); verb=rng.choice(['was born in 1990.','stated that the claim was correct.','filed the application yesterday.','lives in the city.','reported the incident.','appeared before the committee.'])
    text=f'{n} {verb}'; add('PERSON_NAME','sentence-person',text,n,True)
# single-token surnames/given names after strong role/honorific contexts
for _ in range(50):
    n=rng.choice(last); text=f'Mr. {n} stated that the address had changed.'; add('PERSON_NAME','honorific-person',text,n,True)
# PERSON negatives: orgs/headings/roles that can look capitalized.
for v in ['Public Release','Privacy Policy','Data Protection','Machine Learning','Identity Exposure','Research Partner','Security Analyst','Project Manager','Support Case','Case Brief','Document Review']*8:
    text=f'{v} stated that the template was ready.'; add('PERSON_NAME','sentence-person',text,v,False)
for _ in range(70):
    v=org(); text=f'The applicant, {v}, submitted a generic organisation record.'; add('PERSON_NAME','role-person',text,v,False)

# EMPLOYER positives.
for _ in range(170):
    o=org(); text=f'The subject works at {o} as a consultant.'; add('EMPLOYER','employment-org',text,o,True)
for _ in range(170):
    o=org(); text=f'Records were supplied by {o}.'; # make candidate suffix span via direct pattern context-free
    add('EMPLOYER','org-suffix',text,o,True)
# common real-style public bodies
for o in ['Ministry of Health','Department of Social Services','Central District Court','National Research Council','University Medical Center','Regional Police Department','Public Health Authority','Community Education Board']*12:
    text=f'The notice was issued by {o}.'; add('EMPLOYER','org-suffix',text,o,True)
for v in ['Public Release','Research Partner','Human Review','Privacy Red Team','Machine Learning','Data Protection','Case Report','Support Video']*12:
    text=f'The subject works at {v} as a placeholder.'; add('EMPLOYER','employment-org',text,v,False)

# LOCALITY positives.
loc_prefix=['resident of','resides in','lives in','from','near','located in','based in','city of','town of','village of']
for _ in range(260):
    p=rng.choice(places); prefix=rng.choice(loc_prefix); text=f'The applicant is {prefix} {p}, according to the form.'; add('LOCALITY','location-place',text,p,True)
for v in ['the report','the file','the system','Public Release','Research Partner','Support Case','the dataset','Human Review']*15:
    text=f'The applicant is located in {v}, according to the template.'; add('LOCALITY','location-place',text,v,False)

# STREET_ADDRESS positives / negatives.
for _ in range(220):
    a=rng.choice(streets); prefix=rng.choice(['Address:','Residential address:','Home address:','Mailed to','Delivered to'])
    text=f'{prefix} {a}; Phone: +91 90000 10001'; add('STREET_ADDRESS','address-label',text,a,True)
for v in ['Version 12 Build 44','Case 26 Ref 101','Level 4 Privacy 95','Room 2 Section 7']*30:
    text=f'Address: {v}; Phone: +91 90000 10001'; add('STREET_ADDRESS','address-label',text,v,False)

# JOB_TITLE positives / negatives.
for _ in range(220):
    r=rng.choice(roles); prefix=rng.choice(['Occupation: ','Position: ','Job title: ','Role: ','The subject works as a ','The applicant is employed as a '])
    text=f'{prefix}{r}, at the organisation.'; add('JOB_TITLE','job-title',text,r,True)
for v in ['Public Release','Privacy Policy','Machine Learning','Data Protection','Human Review','Research Partner']*20:
    text=f'Role: {v}, in this demo.'; add('JOB_TITLE','job-title',text,v,False)

rng.shuffle(examples)
payload={
 'schema':'veilgraph.semantic-ner-training.v3',
 'purpose':'Broad PII v5 local semantic span-classifier development corpus; synthetic/fictitious only.',
 'license':'VeilGraph generated development corpus; no external/real personal data.',
 'contains_real_pii':False,
 'generation_seed':2603815,
 'examples':examples,
}
OUT.parent.mkdir(parents=True,exist_ok=True); OUT.write_text(json.dumps(payload,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(OUT); print('examples',len(examples))
