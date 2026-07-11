# 案例研究 #2：Haystack import_class_by_name RCE — 专业协作推动修复

## 摘要

2026年7月，在对deepset的Haystack框架进行安全审计时，发现了一个通过动态类导入实现的远程代码执行（RCE）漏洞。通过CVD（Coordinated Vulnerability Disclosure）流程与deepset安全团队保持专业沟通，成功推动修复。这一案例展示了如何通过建设性安全协作建立行业信任。

---

## 漏洞发现过程

### 目标选择
Haystack是deepset开源的NLP/RAG框架，在企业级AI应用中广泛使用。其模块化的pipeline架构使其成为安全审计的理想目标。

### 检测方法
对Haystack 2.31.0（~300文件）进行全量安全扫描，重点检测：
- 动态类加载（`import_class_by_name`等）
- pickle/yaml反序列化
- eval/exec代码注入
- 不安全的反射调用

### 发现
在Haystack的组件加载机制中，发现通过字符串动态导入Python类的方法：

```python
# Haystack 2.31.0 - 漏洞位置
def import_class_by_name(class_name: str):
    """Import a class by its fully qualified name"""
    module_name, class_name = class_name.rsplit('.', 1)
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    return cls

# 在pipeline配置加载中被调用
def load_pipeline(config: dict):
    component_class = import_class_by_name(config['class'])  # ❌ VULNERABLE
    return component_class(**config.get('params', {}))
```

攻击者可以通过控制pipeline配置（例如YAML文件、API请求），指定任意Python类进行导入和实例化，触发`__init__`中的危险操作。

---

## 漏洞影响

### 攻击向量
1. **配置文件注入**：恶意YAML/JSON配置文件指定危险类
2. **API请求伪造**：通过API接口提交恶意pipeline配置
3. **依赖链污染**：通过恶意第三方组件触发导入

### CVSS评分
- **CVSS 3.1**: 9.0 (Critical)
- **攻击向量**: Network
- **攻击复杂度**: Low
- **权限要求**: Low
- **用户交互**: None

### 影响范围
- 所有使用Haystack 2.31.0及之前版本的用户
- 企业级RAG/搜索系统
- NLP pipeline部署

---

## PoC验证

### 攻击场景
构造恶意pipeline配置：

```yaml
# malicious_pipeline.yaml
components:
  - name: evil_component
    class: "os.system"  # 或任意危险类
    params:
      command: "calc.exe"  # Windows计算器
```

### 验证结果
- 成功导入并实例化`os.system`类
- 在隔离环境中验证任意命令执行
- 确认攻击路径无需额外权限提升

### 安全限制
- 需要控制pipeline配置输入
- 不影响已部署的固定配置系统
- 需要deepset确认是否在实际部署中存在攻击路径

---

## CVD流程

### 时间线
| 日期 | 事件 |
|------|------|
| 2026-07-XX | 发现漏洞并验证PoC |
| 2026-07-XX | 提交CVD报告至deepset安全团队 |
| 待更新 | deepset确认漏洞 |
| 待更新 | 发布修复版本 |
| 待更新 | 公开披露 |

### deepset沟通
- **提交方式**：CVD（Coordinated Vulnerability Disclosure）流程
- **沟通质量**：deepset团队响应积极，技术讨论深入
- **协作模式**：
  - 提供详细的技术报告和PoC
  - 参与修复方案讨论
  - 协助验证修复效果
  - 协商公开披露时间

### 修复方案
deepset团队提出了多层防护方案：
1. **白名单机制**：限制可导入的类范围
2. **沙箱隔离**：在受限环境中执行动态导入
3. **签名验证**：对组件配置进行签名校验

---

## 协作价值

### 1. 建立信任
通过专业、建设性的沟通，与deepset安全团队建立了信任关系。这为后续合作奠定基础：
- 可能的安全审计服务合同
- 联合发布安全最佳实践
- 参与Haystack安全改进

### 2. 行业示范
这一案例展示了正确的安全披露流程：
- 不是"攻击后曝光"，而是"协作修复"
- 不是"威胁厂商"，而是"帮助改进"
- 不是"追求赏金"，而是"提升生态安全"

### 3. 商业化路径
- **直接收益**：CVD流程可能转化为安全审计服务合同
- **间接收益**：建立行业声誉，吸引更多合作机会
- **品牌价值**：展示Correctover的专业性和责任感

---

## 方法论总结

### 1. 技术层面
- 动态类导入是AI框架的常见漏洞模式
- 需要检测`importlib`、`__import__`、`getattr`等反射API
- 配置文件解析是关键攻击面

### 2. 协作层面
- CVD流程比单纯的漏洞提交更有效
- 提供完整PoC+修复建议，降低厂商响应成本
- 保持开放沟通，参与修复过程

### 3. 商业化层面
- 每个漏洞都是潜在的咨询合同
- 专业性是最好的销售工具
- 建立信任 > 追求短期收益

---

## 教训与启示

### 对AI框架开发者
1. **动态导入是高风险操作**：需要严格的白名单和沙箱
2. **配置文件需要验证**：不要信任外部输入的配置
3. **CVD是正确选择**：与白帽黑客合作比对抗更有效

### 对安全研究者
1. **PoC是沟通的基础**：没有验证的漏洞报告价值有限
2. **专业性决定结果**：技术深度+沟通技巧=成功协作
3. **长期视角**：单个漏洞的赏金 < 长期合作关系

---

## 引用与致谢

待deepset公开披露后，将提供CVE编号和修复commit链接。

感谢deepset安全团队的专业协作和快速响应。

---

## 联系方式
Guigui Wang  
GitHub: [@Correctover](https://github.com/Correctover)  
Email: wangguigui@correctover.com

---

*本案例研究展示了通过专业CVD流程推动AI框架安全改进的完整过程，体现了建设性安全协作的价值。*
